import socket
import threading
import pyperclip
import time
import uuid
import random
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import sys
import os
from PIL import ImageDraw
from PIL import Image, ImageTk, ImageDraw
import ctypes
import logging  # For debugging purposes
import pystray  # For system tray integration
from pystray import MenuItem as item
import PIL.Image  # For creating tray icon images

# Set up logging
logging.basicConfig(filename='clipboard_sync.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Get the IP address of the current system
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

# Network configuration
LISTENING_PORT = 15411   # Port for continuously listening to incoming requests
SENDING_PORT = 15413     # Port for sending requests and receiving acknowledgments
CLIPBOARD_PORT = 15412   # Port for clipboard data transfer
MAX_UDP_SIZE = 65535  # Maximum size for UDP packet


TARGET_USERS = {}  # Dictionary to store target IPs and their details

# Track the last clipboard content to avoid redundant broadcasts
last_text = ""

# Generate a unique ID for this instance to prevent re-broadcast loops
instance_id = str(uuid.uuid4())

# Lock to prevent race conditions when updating the clipboard
clipboard_lock = threading.Lock()

# Pause flag to control broadcasting and listening
pause_flag = threading.Event()
pause_flag.set()  # Initially not paused

# Variable to track if at least one connection is established
is_connected = threading.Event()

# Store the username
username = None

# Dictionary to store colors for users
user_colors = {}
color_palette = ['red', 'blue', 'green', 'orange', 'purple', 'brown', 'pink', 'cyan', 'magenta', 'yellow']
color_index = 0
color_lock = threading.Lock()

# List of funny usernames
FUNNY_USERNAMES = [
    "TextualTornado", "TypoTitan", "ChatChomper", "WordWhiskers",
    "EmojiExplorer", "LaughingLetter", "TxtWizKid", "SnappyScript",
    "ByteBandit", "PixelPunctuation", "LOLLinguist", "GrammarGator",
    "BuzzingBeeps", "GiggleGlitch", "MemeMorsel", "S'morePixels",
    "ChuckleCharm", "FableFrolic", "ScribbleSprite", "FontFunk",
    "DizzyDialogue", "JollyJabber", "TickleTyper", "PunctuationPirate",
    "GigabyteGiggler", "ChortleChimp", "HappyTypo", "ScrollSorcerer",
    "LOLingLlama", "TypoTreasure"
]

def get_random_funny_username():
    return random.choice(FUNNY_USERNAMES)

def get_next_color():
    global color_index
    with color_lock:
        color = color_palette[color_index % len(color_palette)]
        color_index += 1
    return color

def custom_error_popup(title, message):
    """Creates a custom error popup with specified colors."""
    error_window = tk.Toplevel()
    error_window.title(title)
    error_window.configure(bg="#ff4a38")
    error_window.geometry("400x200")
    error_window.grab_set()  # Make the window modal

    # Message Label
    message_label = tk.Label(error_window, text=message, bg="#ff4a38", fg="#000000",
                             font=("Helvetica", 12, "bold"), wraplength=350, justify='center')
    message_label.pack(pady=40)

    # OK Button
    ok_button = tk.Button(error_window, text="OK", command=error_window.destroy,
                          bg="#d9534f", fg="#ffffff", font=("Helvetica", 10, "bold"),
                          relief='solid', borderwidth=2, highlightbackground="#269144")
    ok_button.pack(pady=10)

def broadcast_clipboard_content():
    global last_text
    while True:
        if not pause_flag.is_set():
            time.sleep(1)
            continue
        try:
            # Get the current clipboard content
            current_text = pyperclip.paste()
            # Lock to prevent race conditions when accessing shared resource (last_text)
            with clipboard_lock:
                # Only broadcast if the clipboard content has changed
                if current_text != last_text:
                    # Truncate clipboard content if it exceeds the maximum allowed size
                    if len(current_text.encode('utf-8')) > MAX_UDP_SIZE:
                        current_text = current_text[:MAX_UDP_SIZE // 2]  # Truncate to fit into a UDP packet
                    last_text = current_text
                    message = f"CLIPBOARD_UPDATE:{instance_id}:{username}:{current_text}"
                    logging.debug(f"Broadcasting clipboard content: {current_text}")
                    # Create a UDP socket for broadcasting the clipboard content
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        # Send the clipboard content to each target IP and specified port
                        for ip in TARGET_USERS:
                            sock.sendto(message.encode('utf-8'), (ip, CLIPBOARD_PORT))
        except Exception as e:
            # Log any errors that occur during broadcasting
            logging.error(f"Error broadcasting clipboard content: {e}")
        # Wait for a random period (between 1 and 2 seconds) before checking the clipboard again
        time.sleep(random.uniform(1, 2))

def listen_for_clipboard_updates():
    global last_text
    # Create a UDP socket for listening to incoming clipboard updates
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the socket to all available network interfaces on the specified port
            sock.bind(('', CLIPBOARD_PORT))
            logging.debug(f"Listening for clipboard updates on port {CLIPBOARD_PORT}...")
        except Exception as e:
            logging.error(f"Error binding to port {CLIPBOARD_PORT} for clipboard updates: {e}")
            return

        while True:
            if not pause_flag.is_set():
                time.sleep(1)
                continue
            try:
                # Receive data from the socket (buffer size of MAX_UDP_SIZE bytes)
                data, addr = sock.recvfrom(MAX_UDP_SIZE)
                # Decode the received data to get the clipboard content
                received_message = data.decode('utf-8')
                if received_message.startswith("CLIPBOARD_UPDATE:"):
                    _, received_id, received_username, received_text = received_message.split(':', 3)

                    # Ignore the message if it was sent by this instance
                    if received_id == instance_id:
                        continue

                    logging.debug(f"Received clipboard content from {addr[0]}:{addr[1]}: {received_text}")
                    # Lock to prevent race conditions when accessing shared resource (last_text)
                    with clipboard_lock:
                        # Only update the clipboard if the received content is different
                        if received_text != last_text:
                            logging.debug("Updating local clipboard with received content...")
                            last_text = received_text
                            pyperclip.copy(received_text)
                            logging.debug(f"Clipboard updated from network: {received_text}")
                            # Update TARGET_USERS with username and copy count
                            if addr[0] in TARGET_USERS:
                                TARGET_USERS[addr[0]]['username'] = received_username
                                TARGET_USERS[addr[0]]['copy_count'] += 1
                                update_connected_users_display()  # Update display after incrementing copy_count
                            else:
                                TARGET_USERS[addr[0]] = {'port': addr[1], 'copy_count': 1, 'username': received_username}
                                # Assign color to new user
                                if received_username not in user_colors:
                                    user_colors[received_username] = get_next_color()
                                update_connected_users_display()
                            # Log the activity with username and copied text
                            log_activity(received_username, f"Copied: {received_text}")
            except Exception as e:
                # Log any errors that occur during receiving
                logging.error(f"Error receiving clipboard content: {e}")

def handle_connection_requests():
    # Create a UDP socket for listening to incoming connection requests
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the socket to the static LISTENING_PORT
            sock.bind(('', LISTENING_PORT))
            logging.debug(f"Listening for connection requests on port {LISTENING_PORT}...")
        except Exception as e:
            logging.error(f"Error binding to port {LISTENING_PORT} for connection requests: {e}")
            return

        while True:
            try:
                # Receive data from the socket (buffer size of 1024 bytes)
                data, addr = sock.recvfrom(1024)
                received_message = data.decode('utf-8')
                logging.debug(f"Received connection request from {addr[0]}:{addr[1]}: {received_message}")
                if received_message.startswith("REQUEST_CONNECTION:"):
                    _, sender_port = received_message.split(':', 1)
                    sender_port = int(sender_port)
                    # Prevent accepting connection from self
                    if addr[0] == local_ip and sender_port == LISTENING_PORT:
                        logging.warning(f"Received connection request from self at {addr[0]}:{sender_port}. Ignoring.")
                        continue
                    # Ask the user if they want to accept the connection
                    result = messagebox.askyesno("Connection Request",
                                                 f"Do you want to connect with user at {addr[0]}:{sender_port}?")
                    if result:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as response_sock:
                            response_message = f"CONNECTION_ACCEPTED:{username}"
                            response_sock.sendto(response_message.encode('utf-8'), (addr[0], sender_port))
                        # Add the user to TARGET_USERS
                        TARGET_USERS[addr[0]] = {'port': sender_port, 'copy_count': 0, 'username': 'Unknown'}
                        logging.debug(f"Accepted connection from {addr[0]}:{sender_port}")
                        is_connected.set()  # Set connection established flag
                        # Assign color for the new user
                        if username not in user_colors:
                            user_colors[username] = get_next_color()
                        # Update the connected users display
                        update_connected_users_display()
                        # Log the activity
                        log_activity(username, f"Connected with {addr[0]}:{sender_port}")
                        # Send current username to the new connection
                        send_username_update(addr[0], sender_port)
                    else:
                        logging.debug(f"Declined connection from {addr[0]}:{sender_port}")
            except Exception as e:
                logging.error(f"Error handling connection request: {e}")

def handle_connection_responses():
    # Create a UDP socket for listening to incoming connection responses and username updates
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the socket to listen for responses on the static SENDING_PORT
            sock.bind(('', SENDING_PORT))
            logging.debug(f"Listening for connection responses and username updates on port {SENDING_PORT}...")
        except Exception as e:
            logging.error(f"Error binding to port {SENDING_PORT} for connection responses: {e}")
            return

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                received_message = data.decode('utf-8')
                if received_message.startswith("CONNECTION_ACCEPTED:"):
                    responder_username = received_message.split(':', 1)[1]
                    # Add the responder to TARGET_USERS
                    TARGET_USERS[addr[0]] = {'port': SENDING_PORT, 'copy_count': 0, 'username': responder_username}
                    logging.debug(f"Connection established with '{responder_username}' at {addr[0]}:{SENDING_PORT}")
                    messagebox.showinfo("Connection Success",
                                        f"Now sharing vibes with '{responder_username}' at {addr[0]}:{SENDING_PORT}! ")
                    is_connected.set()  # Set connection established flag
                    # Assign color for the new user
                    if responder_username not in user_colors:
                        user_colors[responder_username] = get_next_color()
                    # Update the connected users display
                    update_connected_users_display()
                    # Log the activity
                    log_activity(responder_username, f"Connected from {addr[0]}:{SENDING_PORT}")
                    # Send own username to the new connection
                    send_username_update(addr[0], TARGET_USERS[addr[0]]['port'])
                elif received_message.startswith("USERNAME_UPDATE:"):
                    new_username = received_message.split(':', 1)[1]
                    # Update the username in TARGET_USERS
                    if addr[0] in TARGET_USERS:
                        old_username = TARGET_USERS[addr[0]].get('username', 'Unknown')
                        TARGET_USERS[addr[0]]['username'] = new_username
                        # Assign color if not already
                        if new_username not in user_colors:
                            user_colors[new_username] = get_next_color()
                        update_connected_users_display()
                        log_activity(new_username, f"Changed username from {old_username} to {new_username}")
            except Exception as e:
                logging.error(f"Error handling incoming messages: {e}")

def send_connection_request(target_ip):
    if not username:
        custom_error_popup("Oops!", "Please set your username first!")
        return
    if target_ip == local_ip:
        custom_error_popup("Oops!", "BRUHHH you are sending request to yourself")
        logging.warning("User attempted to send connection request to themselves.")
        return
    # Create a UDP socket for sending a connection request
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            # Send connection request with sender's port
            message = f"REQUEST_CONNECTION:{SENDING_PORT}"
            sock.sendto(message.encode('utf-8'), (target_ip, LISTENING_PORT))
            logging.debug(f"Sent connection request to {target_ip}:{LISTENING_PORT}")
            # Removed binding to SENDING_PORT and waiting for response
        except Exception as e:
            logging.error(f"Error sending connection request: {e}")
            if isinstance(e, socket.error) and e.errno == 10048:
                custom_error_popup("Port In Use",
                                   f"Port {SENDING_PORT} is already in use. Please set a different port.")
            else:
                custom_error_popup("Error", f"Failed to send connection request: {e}")

def send_username_update(target_ip, target_port):
    if not username:
        return
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            message = f"USERNAME_UPDATE:{username}"
            sock.sendto(message.encode('utf-8'), (target_ip, target_port))
            logging.debug(f"Sent username update to {target_ip}:{target_port}")
        except Exception as e:
            logging.error(f"Error sending username update: {e}")

def start_threads():
    # Start a thread to broadcast clipboard content
    threading.Thread(target=broadcast_clipboard_content, daemon=True).start()
    # Start a thread to listen for incoming clipboard updates
    threading.Thread(target=listen_for_clipboard_updates, daemon=True).start()
    # Start a thread to handle connection requests
    threading.Thread(target=handle_connection_requests, daemon=True).start()
    # Start a thread to handle connection responses and username updates
    threading.Thread(target=handle_connection_responses, daemon=True).start()

def update_connected_users_display():
    """Updates the connected users table in the GUI."""
    for i in connected_users_tree.get_children():
        connected_users_tree.delete(i)
    for ip, info in TARGET_USERS.items():
        display_username = info.get('username', 'Unknown')
        connected_users_tree.insert('', 'end', values=(display_username, ip, info['port'], info.get('copy_count', 0)))

# GUI Setup
def main():
    global root, username, connected_users_tree, log_text, pause_button, tray_icon

    root = tk.Tk()
    root.title("ClipHilarity Sync")
    root.geometry("800x700")
    root.configure(bg="#70a9c8")  # Set body color

    # Style configuration using ttk
    style = ttk.Style()
    style.theme_use('default')

    # Configure button styles
    style.configure('Custom.TButton',
                    bordercolor='#269144',
                    borderwidth=2,
                    focusthickness=3,
                    focuscolor='none',
                    padding=6)
    style.map('Custom.TButton',
              foreground=[('active', '#ffffff')],
              background=[('active', '#d9534f')])

    # Display the logo at the top of the window
    image_path = "logo.png"
    if os.path.exists(image_path):
        logo_image = Image.open(image_path)
        logo_image = logo_image.resize((100, 100), Image.LANCZOS)  # Use Image.LANCZOS
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(root, image=logo_photo, bg="#70a9c8")
        logo_label.image = logo_photo  # Keep a reference to prevent garbage collection
        logo_label.pack(pady=10)

    # Frame for Port and Username
    settings_frame = tk.Frame(root, bg="#70a9c8")
    settings_frame.pack(pady=10)

    # Port Entry (disabled since now using static ports)
    port_label = tk.Label(settings_frame, text="🔧 Communication Port:", font=("Helvetica", 10, "bold"),
                          bg="#70a9c8")
    port_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')
    port_entry = tk.Entry(settings_frame, width=30, font=("Helvetica", 10, "bold"), bd=2, relief='solid',
                          highlightbackground="#269144", state='disabled')  # Disable port entry
    port_entry.grid(row=0, column=1, padx=5, pady=5)

    # Username Entry
    username_label = tk.Label(settings_frame, text="🧑‍🎤 Your Funky Username:", font=("Helvetica", 10, "bold"),
                              bg="#70a9c8")
    username_label.grid(row=1, column=0, padx=5, pady=5, sticky='e')
    username_entry = tk.Entry(settings_frame, width=30, font=("Helvetica", 10, "bold"), bd=2, relief='solid',
                              highlightbackground="#269144")
    username_entry.grid(row=1, column=1, padx=5, pady=5)

    # Button to Set Username
    set_username_button = ttk.Button(settings_frame, text="🎉 Set Username", style='Custom.TButton',
                                     command=lambda: set_username())
    set_username_button.grid(row=1, column=2, padx=5, pady=5)

    # Display the username and local IP address at the top of the dashboard
    user_label = tk.Label(root, text="🧑‍🎤 Your Cool Alias: Not Set", font=("Helvetica", 12, "bold"),
                          bg="#70a9c8")
    user_label.pack(pady=5)

    ip_label = tk.Label(root, text=f"🌐 Your Secret Lair IP: {local_ip}:{LISTENING_PORT}", font=("Helvetica", 12, "bold"),
                        bg="#70a9c8")
    ip_label.pack(pady=5)

    # Add a button to send a connection request
    invite_button = ttk.Button(root, text="👫 Invite a Buddy", style='Custom.TButton',
                               state='disabled',
                               command=lambda: invite_buddy())
    invite_button.pack(pady=10)

    # Function to handle inviting a buddy
    def invite_buddy():
        # Prompt the user to enter the target IP
        invite_window = tk.Toplevel(root)
        invite_window.title("Invite a Buddy")
        invite_window.geometry("400x200")
        invite_window.configure(bg="#70a9c8")
        invite_window.grab_set()  # Make the window modal

        # Bind Enter key to send_button
        invite_window.bind('<Return>', lambda event: send_button.invoke())

        # IP Entry
        target_ip_label = tk.Label(invite_window, text="🎯 Target IP Address:", font=("Helvetica", 10, "bold"),
                                   bg="#70a9c8")
        target_ip_label.pack(pady=10)
        target_ip_entry = tk.Entry(invite_window, width=30, font=("Helvetica", 10, "bold"), bd=2,
                                   relief='solid', highlightbackground="#269144")
        target_ip_entry.pack(pady=5)
        target_ip_entry.focus_set()

        # Button to Send Connection Request
        send_button = ttk.Button(invite_window, text="📨 Send Invite", style='Custom.TButton',
                                 command=lambda: send_request())
        send_button.pack(pady=20)

        def send_request():
            target_ip = target_ip_entry.get().strip()
            if not target_ip:
                custom_error_popup("Incomplete Information", "Please enter the target IP address.")
                return
            # Send the connection request to static port 15412
            invite_window.destroy()
            send_connection_request(target_ip)

    # Add a label to indicate listening for incoming requests
    listening_label = tk.Label(root, text="🕶️ Chilling with my buddies anyone else wanna join...",
                                font=("Helvetica", 10, "italic"), bg="#70a9c8")
    listening_label.pack(pady=5)

    # Add a Pause button to pause or resume syncing only after connection is established
    def toggle_pause():
        if pause_flag.is_set():
            pause_flag.clear()
            pause_button.config(text="⏯️ Resume Sync")
            log_activity("System", "Clipboard syncing is now on snooze mode.")
        else:
            pause_flag.set()
            pause_button.config(text="⏸️ Pause Sync")
            log_activity("System", "Clipboard syncing resumed. Back in action!")

    pause_button = ttk.Button(root, text="⏸️ Pause Sync", style='Custom.TButton', command=toggle_pause)
    pause_button.pack(pady=10)
    pause_button.pack_forget()  # Hide the pause button initially

    # Add a scrolled text widget for logs
    log_frame = tk.Frame(root, bg="#70a9c8")
    log_frame.pack(pady=10, fill=tk.BOTH, expand=True)

    log_label = tk.Label(log_frame, text="📝 Connection Logs:", font=("Helvetica", 12, "bold"),
                         bg="#70a9c8")
    log_label.pack(anchor='w')

    log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled', height=10,
                                        bg="#ffffff", fg="#000000", font=("Helvetica", 10, "bold"))
    log_text.pack(fill=tk.BOTH, expand=True)

    # Function to log activities with colors
    def log_activity(user, message):
        """Logs activities in the GUI with the user's color."""
        log_text.config(state='normal')
        if user in user_colors:
            color = user_colors[user]
        else:
            color = get_next_color()
            user_colors[user] = color
        log_text.tag_config(user, foreground=color, font=("Helvetica", 10, "bold"))
        log_entry = f"{user}: {message}\n"
        log_text.insert(tk.END, log_entry, user)
        log_text.config(state='disabled')
        log_text.yview(tk.END)
        logging.info(log_entry.strip())  # Add this line to log to the file

    # Add a Treeview to display connected users
    connected_users_label = tk.Label(root, text="👥 Connected Users:", font=("Helvetica", 12, "bold"),
                                     bg="#70a9c8")
    connected_users_label.pack(pady=5)

    connected_users_tree = ttk.Treeview(root, columns=("Username", "IP Address", "Port", "Copy Count"), show='headings')
    connected_users_tree.heading("Username", text="Username")
    connected_users_tree.heading("IP Address", text="IP Address")
    connected_users_tree.heading("Port", text="Port")
    connected_users_tree.heading("Copy Count", text="Copy Count")
    connected_users_tree.pack(pady=5, fill=tk.BOTH, expand=True)

    # Start threads for clipboard sync and connection handling are initiated after setting username and port

    def set_username():
        global username
        entered_username = username_entry.get().strip()
        if not entered_username:
            # Assign a random funny username if none provided
            username = get_random_funny_username()
            messagebox.showinfo("Username Assigned", f"No username entered. Assigned '{username}' for you!")
        else:
            username = entered_username
        # Disable the username entry and button after setting
        username_entry.delete(0, tk.END)
        username_entry.config(state='disabled')
        set_username_button.config(state='disabled')
        # Display the username at the top of the dashboard
        user_label.config(text=f"🧑‍🎤 Your Cool Alias: {username}")
        # Enable the Invite button
        invite_button.config(state='normal')
        # If there are existing connections, send username updates
        for ip, info in TARGET_USERS.items():
            send_username_update(ip, info['port'])

    def on_close():
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            tray_icon.stop()  # Ensure tray icon is removed
            sys.exit()

    root.protocol("WM_DELETE_WINDOW", on_close)

    def check_ready():
        """Enable the Invite button if Username is set."""
        if username:
            invite_button.config(state='normal')
            pause_button.pack(pady=10)  # Show the pause button once ready
        else:
            invite_button.config(state='disabled')
        root.after(1000, check_ready)

    # Start checking if Username is set
    root.after(1000, check_ready)

    # Bind Enter key to Set Username button
    root.bind('<Return>', lambda event: set_username() if username_entry.focus_get() else None)

    # **Enhancement 3: Add a button to minimize to system tray**
    def minimize_to_tray():
        root.withdraw()
        tray_icon.visible = True

    # Create tray icon
    def create_tray_icon():
        image = PIL.Image.new('RGB', (64, 64), color='blue')
        draw = PIL.ImageDraw.Draw(image)
        draw.rectangle((0, 0, 64, 64), fill='blue')
        draw.text((10, 25), "CT", fill='white')  # Example text
        menu = (
            item('Restore', restore_window),
            item('Exit', exit_application)
        )
        tray = pystray.Icon("ClipHilarity Sync", image, "ClipHilarity Sync", menu)
        return tray

    def restore_window(icon, item):
        icon.visible = False
        root.deiconify()

    def exit_application(icon, item):
        icon.stop()
        sys.exit()

    # Add Minimize to Tray button
    minimize_tray_button = ttk.Button(root, text="🔻 Minimize to Tray", style='Custom.TButton',
                                     command=lambda: minimize_to_tray())
    minimize_tray_button.pack(pady=10)

    # Initialize tray icon
    tray_icon = create_tray_icon()

    def show_tray_icon():
        tray_thread = threading.Thread(target=tray_icon.run, daemon=True)
        tray_thread.start()

    # Start the tray icon thread
    show_tray_icon()

    # Start the threads for clipboard sync and connection handling
    start_threads()

    root.mainloop()

if __name__ == "__main__":
    main()
    # Keep the threads running in the background even after closing the GUI
    while True:
        time.sleep(1)


