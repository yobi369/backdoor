# Backdoor Project

## Overview
This project implements a reverse shell that allows command execution on a remote server. It has been enhanced with basic malware analysis capabilities, focusing on static analysis of files. The tool provides functionalities such as file upload/download, command history management, basic authentication, and new commands for file hashing and string extraction. Communication is secured using SSL, and all data is encrypted.

## Features
- **Command Execution**: Execute a variety of shell commands on the remote server.
- **File Management**: Upload and download files securely.
- **Static Malware Analysis**:
    - `analyze_strings [filepath]`: Extract printable strings from a specified file.
    - `get_file_hash [filepath] [md5|sha1|sha256]`: Calculate and display the MD5, SHA1, or SHA256 hash of a file. Defaults to SHA256.
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
- `analyze_strings [filepath]`: Extract printable strings from the specified file on the server.
- `get_file_hash [filepath] [md5|sha1|sha256]`: Get the specified hash (default sha256) of the file on the server.
- `clear`: Clear the shell output.
- `quit`: Exit the shell.
- `help`: Display help information about available commands.
- `history`: List all executed commands.
- `clear_history`: Clear the command history.

### Windows Specific Commands (if applicable)
- `list_processes_win`: List running processes on the Windows host.
- `proc_details_win [PID]`: Get details for a specific process ID on Windows.
- `read_mem_win [PID] [hex_address] [size]`: Read memory from a process at a given hex address (size in bytes).
- `scan_mem_win [PID] [string|bytes] [pattern]`: Scan process memory for a string or hex byte pattern.

## Security Considerations
- This tool is powerful and can be used for malicious purposes if it falls into the wrong hands. Ensure it is used responsibly and ethically.
- Operations involving process memory access (`read_mem_win`, `scan_mem_win`) on Windows may require appropriate privileges and can potentially crash the target process or the tool itself if not handled carefully or if invalid parameters are provided. Use with caution.
- Ensure that the server IP and password are kept secure and not hardcoded in the source code. Use environment variables to manage sensitive information.
- Regularly update the encryption key and ensure it is stored securely.

## Logging
All actions and errors are logged in `reverse_shell.log` for monitoring and debugging purposes.

## Usage
1. Set the required environment variables.
2. Run the `backdoor.py` script.
3. Connect to the server and authenticate using the provided password.
4. Use the available commands as needed.
