# ClipNet

*Synchronize your clipboard across multiple devices seamlessly.*

![ClipNet Logo](path_to_logo_image)

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [GUI Overview](#gui-overview)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Introduction

**ClipNet** is a real-time clipboard synchronization tool that allows you to share your clipboard content across multiple devices on the same network. Whether you're working on a desktop, laptop, or any other device, ClipNet ensures that your clipboard is always in sync, boosting productivity and collaboration.

## Features

- **Real-time Synchronization**: Automatically updates clipboard content across all connected devices.
- **User-Friendly GUI**: Easy-to-use interface built with Tkinter for seamless interaction.
- **Secure Connection**: Establishes connections using a three-way handshake protocol.
- **Custom Usernames**: Set your own funky username or get assigned a random funny one.
- **Activity Logs**: Keep track of clipboard activities with timestamps and user details.
- **Connected Users Display**: View all connected peers and their copy counts.
- **Active Users Discovery**: Automatically discovers active users on the network.
- **Pause Sync**: Ability to pause and resume synchronization as needed.
- **System Tray Integration**: Minimizes to system tray for unobtrusive operation.

## Installation

### Prerequisites

- Python 3.x
- Required Python packages:
    - `tkinter`
    - `Pillow`
    - `pystray`

### Steps

1. **Clone the Repository**

     ```bash
     git clone https://github.com/yourusername/clipnet.git
     ```

2. **Navigate to the Project Directory**

     ```bash
     cd clipnet
     ```

3. **Install Dependencies**

     ```bash
     pip install -r requirements.txt
     ```

4. **Run the Application**

     ```bash
     python main.py
     ```

## Usage

1. **Launch ClipNet**

     Run `main.py` to start the application.

2. **Set Your Username**

     - Enter a unique and funky username.
     - Click on the "🎉 Set Username" button.

     ![Set Username](path_to_set_username_image)

3. **Invite a Buddy**

     - Click on the "👫 Invite a Buddy" button.
     - Enter the IP address of the device you want to connect with.

     ![Invite Buddy](path_to_invite_buddy_image)

4. **View Connected Users**

     - Check the "Connected Users" section to see all the users you're synced with.

     ![Connected Users](path_to_connected_users_image)

5. **Clipboard Synchronization**

     - Copy any text, and it will automatically synchronize across all connected devices.
     - View the clipboard logs in the "📝 Clipboard Logs" section.

     ![Clipboard Logs](path_to_clipboard_logs_image)

6. **Pause and Resume Sync**

     - Use the "⏸️ Pause Sync" button to pause synchronization.
     - Click again to resume.

## GUI Overview

- **Logo and Title**: Located at the top for branding.
- **Settings Frame**: Contains fields to set your username.
- **User Information**: Displays your username and local IP address.
- **Invitation Button**: Allows you to invite other users.
- **Pause Button**: Pauses or resumes synchronization.
- **Clipboard Logs**: Shows the clipboard history with timestamps.
- **Connected Users Table**: Lists all connected users with details.
- **Active Users Table**: Displays users available for connection.

![GUI Overview](path_to_gui_overview_image)

## Configuration

- **Ports Used**:
    - `LISTENING_PORT`: 15411 (For incoming requests)
    - `SENDING_PORT`: 15413 (For sending requests)
    - `CLIPBOARD_PORT`: 15412 (For clipboard data transfer)
    - `HANDSHAKE_PORT`: 17032 (For three-way handshake)

- **Adjusting Ports**: Modify the constants in `main.py` if port conflicts occur.

## Troubleshooting

- **Cannot Connect to a Device**:
    - Ensure both devices are on the same network.
    - Check firewall settings to allow necessary ports.
    
- **Clipboard Not Synchronizing**:
    - Verify that synchronization is not paused.
    - Restart the application on both devices.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes.

## License

This project is licensed under the MIT License.

## Acknowledgments

- **Icons**: Thanks to [Icons8](https://icons8.com) for the beautiful icons.
- **Libraries**:
    - [Tkinter](https://docs.python.org/3/library/tkinter.html)
    - [Pillow](https://python-pillow.org/)
    - [Pystray](https://github.com/moses-palmer/pystray)
