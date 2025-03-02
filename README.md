# Backdoor Project

## Overview
This project implements a reverse shell that allows command execution on a remote server. It provides functionalities such as file upload/download, command history management, and basic authentication. The communication is secured using SSL, and all data is encrypted for confidentiality.

## Features
- **Command Execution**: Execute a variety of shell commands on the remote server.
- **File Management**: Upload and download files securely.
- **Command History**: Keep track of executed commands and clear history when needed.
- **Help Command**: Display available commands and their usage.
- **Secure Communication**: Utilizes SSL for secure connections and encryption for data transmission.

## Environment Variables
To enhance security, the following environment variables should be set:
- `SERVER_IP`: The IP address of the server to connect to (default is `127.0.0.1` for testing).
- `SERVER_PORT`: The port number for the server connection (default is `5555`).
- `BACKDOOR_PASSWORD`: The password required for authentication (default is `your_secure_password`).

## Available Commands
- `cd [directory]`: Change the current directory.
- `upload [file]`: Upload a file to the server.
- `download [file]`: Download a file from the server.
- `clear`: Clear the shell output.
- `quit`: Exit the shell.
- `help`: Display help information about available commands.
- `history`: List all executed commands.
- `clear_history`: Clear the command history.

## Security Considerations
- Ensure that the server IP and password are kept secure and not hardcoded in the source code. Use environment variables to manage sensitive information.
- Regularly update the encryption key and ensure it is stored securely.

## Logging
All actions and errors are logged in `reverse_shell.log` for monitoring and debugging purposes.

## Usage
1. Set the required environment variables.
2. Run the `backdoor.py` script.
3. Connect to the server and authenticate using the provided password.
4. Use the available commands as needed.
