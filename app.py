from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response, send_file, abort, send_from_directory, make_response
from functools import wraps
import os
import subprocess
import json
import re
import time
import secrets
import hashlib
import shutil
import threading
import queue
import stat
import uuid
import zipfile
import io
import datetime
import socket
import logging
from logging.handlers import RotatingFileHandler
from werkzeug.utils import secure_filename
import psutil
import hmac
import sys
import traceback
from collections import defaultdict
from crontab import CronTab

# Flask app setup
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# status and queues
server_creation_status = {}
creation_queues = {}

# protected images and logs directory
PROTECTED_IMAGES_DIR = 'protected_imgs'
LOGS_DIR = 'logs'

# Server configuration storage
SERVER_CONFIG_PATH = 'server_configs.json'
CREATION_SESSIONS_FILE = 'creation_sessions.json'

# Authentication / User management
USERS_FILE = 'users.json'

# List of banned players and their details 
# This can be put in other directory
# Just needs some touch up in the code
BANNED_PLAYERS_FILE = 'banned_players.json'

# Ensure logs directory exists
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

# Set up logging
log_file = os.path.join(LOGS_DIR, 'pz_manager.log')
file_handler = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=10)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

logger = logging.getLogger('pz_manager')
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

# Tools
def is_binary_file(file_path, sample_size=8192):
    """
    Check if a file is binary by reading a sample of bytes and looking for null bytes
    or a high percentage of non-text characters.
    """
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
            
        # Check for null bytes (common in binary files)
        if b'\x00' in sample:
            return True
            
        # Check text file extensions
        text_extensions = ['.txt', '.log', '.cfg', '.ini', '.lua', '.json', '.xml', '.html', '.js', '.css', '.sh', '.bat', '.ps1', '.py', '.java']
        if any(file_path.lower().endswith(ext) for ext in text_extensions):
            return False
            
        # Try to decode as UTF-8
        try:
            sample.decode('utf-8')
            return False  # Successfully decoded as UTF-8
        except UnicodeDecodeError:
            # Not UTF-8, may be binary or another encoding
            pass
            
        # Count printable ASCII characters
        printable_chars = 0
        for byte in sample:
            if 32 <= byte <= 126:  # ASCII printable range
                printable_chars += 1
                
        # If less than 70% of characters are printable ASCII, consider it binary
        if printable_chars / len(sample) < 0.7:
            return True
            
        return False
    except Exception:
        # If any error occurs, default to assuming it's a binary file
        return True

def update_server_statuses():
    data = load_servers()
    
    for server_name in data["servers"]:
        current_status = get_server_status(server_name)
        data["servers"][server_name]["status"] = current_status
    
    save_servers(data)
    logger.debug("Updated status for all servers")

def clear_server_status_markers(server_name):
    """
    Clear all status marker files for a server
    
    Args:
        server_name: Name of the server
    """
    try:
        # Remove any marker files
        for status in ["restarting", "stopping"]:
            marker_path = f'/tmp/pzserver-{server_name}-{status}'
            if os.path.exists(marker_path):
                os.remove(marker_path)
                logger.info(f"Removed {status} marker for server {server_name}")
        return True
    except Exception as e:
        logger.error(f"Error clearing status markers for {server_name}: {str(e)}")
        return False

def set_server_status_marker(server_name, status):
    """
    Create a marker file to indicate the server is in a specific transitional state
    
    Args:
        server_name: Name of the server
        status: Status to set (restarting, stopping)
    """
    try:
        if status not in ["restarting", "stopping"]:
            return
            
        marker_path = f'/tmp/pzserver-{server_name}-{status}'
        
        # Create the marker file
        with open(marker_path, 'w') as f:
            f.write(str(time.time()))
            
        logger.info(f"Created {status} marker for server {server_name}")
        return True
    except Exception as e:
        logger.error(f"Error creating status marker for {server_name}: {str(e)}")
        return False

def is_admin(username):
    try:
        with open(USERS_FILE, 'r') as f:
            data = json.load(f)
        
        return data["users"].get(username, {}).get("is_admin", False)
    except Exception as e:
        logger.error(f"Admin check failed: {str(e)}")
        return False

def save_servers(data):
    try:
        with open(SERVER_CONFIG_PATH, 'w') as f:
            json.dump(data, f, indent=4)
        logger.debug("Server configuration saved")
    except IOError as e:
        logger.error(f"Failed to save server configuration: {str(e)}")

@app.context_processor
def utility_processor():
    """Make utility functions available to all templates"""
    return {
        'get_secure_image_url': get_secure_image_url
    }

def get_secure_image_url(image_path, expiry=3600):
    """Generate a secure URL for a protected image"""
    try:
        # Add default extension if missing
        if '.' not in image_path:
            image_path = f"{image_path}.png"
        
        full_path = os.path.join(PROTECTED_IMAGES_DIR, image_path)
        if not os.path.exists(full_path):
            logger.warning(f"Protected image not found: {image_path}")
            return None
        
        expiry_time = int(time.time()) + expiry
        message = f"{expiry_time}:{image_path}"
        
        signature = hmac.new(
            app.secret_key.encode(),
            message.encode(),
            'sha256'
        ).hexdigest()
        
        return url_for(
            'serve_protected_image', 
            path=image_path, 
            expires=expiry_time, 
            signature=signature
        )
    except Exception as e:
        logger.error(f"Error generating secure image URL: {str(e)}")
        return None

def get_creation_session(creation_id):
    try:
        data = load_creation_sessions()
        
        if creation_id in data["sessions"]:
            # Update last accessed time
            data["sessions"][creation_id]["last_accessed"] = time.time()
            save_creation_sessions(data)
            
            return data["sessions"][creation_id]
        
        return None
    except Exception as e:
        logger.error(f"Failed to retrieve creation session {creation_id}: {str(e)}")
        return None

def update_creation_session(creation_id, status="completed", server_name=None):
    try:
        data = load_creation_sessions()
        
        if creation_id in data["sessions"]:
            data["sessions"][creation_id]["status"] = status
            data["sessions"][creation_id]["last_accessed"] = time.time()
            
            if server_name:
                data["sessions"][creation_id]["server_name"] = server_name
                
            save_creation_sessions(data)
            
            # Update server status if completed
            if status == "completed" and server_name:
                server_data = load_servers()
                if server_name in server_data["servers"]:
                    server_data["servers"][server_name]["marked"] = "finish"
                    server_data["servers"][server_name]["status"] = "stopped"
                    save_servers(server_data)
            
            logger.debug(f"Creation session updated: {creation_id} status={status}")
            return True
        
        logger.warning(f"Attempted to update non-existent creation session: {creation_id}")
        return False
    except Exception as e:
        logger.error(f"Failed to update creation session {creation_id}: {str(e)}")
        return False

def store_creation_session(creation_id, server_name, username):
    try:
        data = load_creation_sessions()
        
        data["sessions"][creation_id] = {
            "server_name": server_name,
            "username": username,
            "started_at": time.time(),
            "last_accessed": time.time(),
            "status": "running"
        }
        
        save_creation_sessions(data)
        logger.info(f"Creation session stored: {creation_id} for server {server_name} by user {username}")
    except Exception as e:
        logger.error(f"Failed to store creation session: {str(e)}")

def save_creation_sessions(data):
    try:
        with open(CREATION_SESSIONS_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        logger.debug("Creation sessions saved")
    except IOError as e:
        logger.error(f"Failed to save creation sessions: {str(e)}")

def cleanup_idle_creation_queues(max_idle_time=3600):
    """Clean up creation queues that have been idle for too long"""
    try:
        current_time = time.time()
        idle_creation_ids = [
            creation_id for creation_id, status in server_creation_status.items()
            if status.get('complete', False) or (current_time - status.get('started_at', 0) > max_idle_time)
        ]
        
        for creation_id in idle_creation_ids:
            if creation_id in creation_queues:
                while not creation_queues[creation_id].empty():
                    creation_queues[creation_id].get_nowait()
                del creation_queues[creation_id]
            
            if creation_id in server_creation_status:
                del server_creation_status[creation_id]
        
        if idle_creation_ids:
            logger.info(f"Cleaned up {len(idle_creation_ids)} idle creation queues")
    except Exception as e:
        logger.error(f"Error in cleanup_idle_creation_queues: {str(e)}")

def load_creation_sessions():
    try:
        if not os.path.exists(CREATION_SESSIONS_FILE):
            with open(CREATION_SESSIONS_FILE, 'w') as f:
                json.dump({"sessions": {}}, f)
            logger.info(f"Created new empty creation sessions file: {CREATION_SESSIONS_FILE}")
            return {"sessions": {}}
        
        with open(CREATION_SESSIONS_FILE, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load creation sessions: {str(e)}")
        return {"sessions": {}}

def set_directory_permissions():
    """
    Sets write permissions for specific directories and their files.
    Returns success status and message.
    """
    logger = logging.getLogger('pz_manager')
    
    directories = [
        'logs',
        'protected_imgs',
        'save',
        'save/lua',
        'static',
        'static/css',
        'static/js',
        'templates'
    ]
    
    try:
        for directory in directories:
            # Ensure directory exists
            if not os.path.exists(directory):
                os.makedirs(directory)
                logger.info(f"Created directory: {directory}")
                
            # Set directory permissions (755 = rwxr-xr-x)
            os.chmod(directory, 0o755)
            logger.info(f"Set permissions for directory: {directory}")
            
            # Set permissions for files in directory
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Set file permissions (644 = rw-r--r--)
                    os.chmod(file_path, 0o644)
            
        logger.info("Successfully set permissions for all directories and files")
        return True, "Directory permissions set successfully"
        
    except PermissionError as e:
        logger.error(f"Permission error: {str(e)}")
        return False, f"Permission error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error setting permissions: {str(e)}")
        return False, f"Unexpected error setting permissions: {str(e)}"

def is_player_banned(server_name, username):
    """Check if a player is banned on a specific server"""
    try:
        banned_players = get_banned_players(server_name)
        return any(player["username"] == username for player in banned_players)
    except Exception as e:
        logger.error(f"Error checking banned status for {username} on {server_name}: {str(e)}")
        return False

def save_banned_players(data):
    """Save banned players data to JSON file"""
    try:
        with open(BANNED_PLAYERS_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        logger.debug("Banned players data saved")
    except IOError as e:
        logger.error(f"Failed to save banned players file: {str(e)}")

def load_banned_players():
    """Load banned players data from JSON file"""
    init_banned_players_file()
    try:
        with open(BANNED_PLAYERS_FILE, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error loading banned players file: {str(e)}")
        return {"servers": {}}

# Authentication Functions
def init_users_file():
    try:
        if not os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'w') as f:
                json.dump({"users": {}}, f)
            
            hash_password = hashlib.sha256("shan123".encode()).hexdigest()
            add_user("admin", hash_password, True)
            logger.info("Initialized users file with default admin user")
    except Exception as e:
        logger.error(f"User file initialization failed: {str(e)}")

def initiate_first_load():
    """
    Sets up the firewall for Project Zomboid server manager and installs AWS CLI.
    - Checks if UFW is active
    - Enables UFW if inactive
    - Adds necessary firewall rules for the web interface and SSH
    - Opens ports 22 (SSH) and 5000 (web interface)
    - Installs AWS CLI v2 if not already installed
    """
    logger = logging.getLogger('pz_manager')
    
    try:
        # Check current UFW status
        logger.info("Checking UFW status...")
        status_result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
        
        # If UFW is inactive, enable it
        if "inactive" in status_result.stdout:
            logger.info("UFW is inactive. Enabling...")

            set_directory_permissions()
            
            # First add rules before enabling to prevent lockout
            logger.info("Adding essential firewall rules...")
            
            # Add rule for SSH (port 22) to prevent lockout
            subprocess.run(['sudo', 'ufw', 'allow', '22/tcp'], check=True)
            logger.info("Added rule for SSH (port 22)")
            
            # Add rule for web interface (port 5000)
            subprocess.run(['sudo', 'ufw', 'allow', '5000/tcp'], check=True)
            logger.info("Added rule for web interface (port 5000)")
            
            # Enable UFW with yes response
            logger.info("Enabling UFW...")
            enable_process = subprocess.Popen(['sudo', 'ufw', 'enable'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = enable_process.communicate(input=b'y\n')
            
            # Log the output of the enable command
            logger.debug(f"UFW enable stdout: {stdout.decode().strip()}")
            logger.debug(f"UFW enable stderr: {stderr.decode().strip()}")
            
            # Wait for UFW to initialize
            time.sleep(2)
            
            # Verify UFW is now active
            verify_result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
            
            if "active" in verify_result.stdout:
                logger.info("UFW successfully enabled")
            else:
                logger.error("Failed to enable UFW")
                
            logger.info("Firewall configuration completed")
        else:
            # UFW is already active, just ensure rules are in place
            logger.info("UFW is already active. Verifying rules...")
            
            # Check if SSH rule exists, add if missing
            if "22/tcp" not in status_result.stdout:
                subprocess.run(['sudo', 'ufw', 'allow', '22/tcp'], check=True)
                logger.info("Added missing rule for SSH (port 22)")
            
            # Check if web interface rule exists, add if missing
            if "5000/tcp" not in status_result.stdout:
                subprocess.run(['sudo', 'ufw', 'allow', '5000/tcp'], check=True)
                logger.info("Added missing rule for web interface (port 5000)")
                
            logger.info("Firewall rules verified")
        
        # Check if AWS CLI is already installed
        aws_check = subprocess.run(['aws', '--version'], capture_output=True, text=True)
        if aws_check.returncode == 0:
            logger.info(f"AWS CLI already installed: {aws_check.stdout.strip()}")
        else:
            # Install AWS CLI v2
            logger.info("Installing AWS CLI v2...")
            
            # Download AWS CLI installer
            subprocess.run(['curl', 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip', '-o', 'awscliv2.zip'], check=True)
            
            # Install unzip if not present with automatic confirmation
            subprocess.run(['sudo', 'apt-get', 'update', '-y'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', '-y', 'unzip'], check=True)
            
            # Unzip the installer with auto-confirmation
            subprocess.run(['unzip', '-o', '-q', 'awscliv2.zip'], check=True)
            
            # Run the install script with auto-confirmation
            subprocess.run(['sudo', './aws/install', '--update', '--install-dir', '/usr/local/aws-cli', '--bin-dir', '/usr/local/bin'], check=True)
            
            # Clean up installation files
            subprocess.run(['rm', '-rf', 'aws', 'awscliv2.zip'], check=True)
            
            # Verify AWS CLI installation
            aws_version = subprocess.run(['aws', '--version'], capture_output=True, text=True)
            logger.info(f"AWS CLI installed: {aws_version.stdout.strip()}")
            
        return True, "Firewall configured and AWS CLI installed successfully"
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Subprocess error during setup: {str(e)}")
        return False, f"Subprocess error during setup: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error during setup: {str(e)}")
        return False, f"Unexpected error during setup: {str(e)}"

def init_banned_players_file():
    """Initialize the banned players file if it doesn't exist"""
    try:
        if not os.path.exists(BANNED_PLAYERS_FILE):
            with open(BANNED_PLAYERS_FILE, 'w') as f:
                json.dump({"servers": {}}, f)
            logger.info("Initialized banned players file")
    except Exception as e:
        logger.error(f"Error initializing banned players file: {str(e)}")

def add_user(username, password_hash, is_admin=False):
    try:
        with open(USERS_FILE, 'r') as f:
            data = json.load(f)
        
        data["users"][username] = {
            "password_hash": password_hash,
            "is_admin": is_admin
        }
        
        with open(USERS_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        
        logger.info(f"Added user: {username} (admin: {is_admin})")
    except Exception as e:
        logger.error(f"User creation failed: {str(e)}")

def authenticate_user(username, password):
    try:
        with open(USERS_FILE, 'r') as f:
            data = json.load(f)
        
        if username in data["users"]:
            stored_hash = data["users"][username]["password_hash"]
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if stored_hash == password_hash:
                logger.info(f"Authentication successful: {username}")
                return True
        
        logger.warning(f"Authentication failed: {username}")
        return False
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return False
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page')
            logger.warning(f"Unauthorized access attempt to {request.path} by {request.remote_addr}")
            return redirect(url_for('login'))
        
        logger.info(f"Authorized access to {request.path} by user {session['username']}")
        return f(*args, **kwargs)
    
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or not is_admin(session['username']):
            flash('Admin privileges required')
            user = session.get('username', 'unknown')
            logger.warning(f"{user} (non-admin) accessed {request.path}")
            return redirect(url_for('dashboard'))
        
        logger.info(f"Admin {session['username']} accessed {request.path}")
        return f(*args, **kwargs)

    return decorated_function

# Server Management
def load_servers():
    try:
        if not os.path.exists(SERVER_CONFIG_PATH):
            with open(SERVER_CONFIG_PATH, 'w') as f:
                json.dump({"servers": {}}, f)
                os.chmod(SERVER_CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
            logger.info(f"Created new empty server configuration file: {SERVER_CONFIG_PATH}")
            return {"servers": {}}
        
        with open(SERVER_CONFIG_PATH, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load server configuration: {str(e)}")
        return {"servers": {}}

@app.route('/secure-img/<path:path>')
def serve_protected_image(path):
    """Serve protected images with security verification"""
    # Get query parameters
    expires = request.args.get('expires', '0')
    signature = request.args.get('signature', '')
    
    try:
        # Verify timestamp hasn't expired
        expiry_time = int(expires)
        if time.time() > expiry_time:
            logger.warning(f"Protected image access denied - expired link: {path}")
            abort(403)  # Forbidden - link expired
            
        # Verify signature
        message = f"{expires}:{path}"
        expected_signature = hmac.new(
            app.secret_key.encode(),
            message.encode(),
            'sha256'
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning(f"Protected image access denied - invalid signature: {path}")
            abort(403)  # Forbidden - invalid signature
            
        # If validation passes, serve the file
        logger.debug(f"Serving protected image: {path}")
        return send_from_directory(PROTECTED_IMAGES_DIR, path)
            
    except (ValueError, TypeError):
        logger.warning(f"Bad request for protected image: {path}")
        abort(400)  # Bad request

def async_create_server(server_name, admin_password, server_password, port, query_port, rcon_port, creation_id):
    try:
        logger.info(f"[{creation_id}] Starting server creation process for {server_name}")

        update_creation_session(creation_id, "running", server_name)
        
        # If server_name is blank, generate a default one
        data = load_servers()
        if not server_name.strip():
            existing_servers = len(data["servers"])
            server_name = f"pzserver{existing_servers+1:02d}"
            logger.info(f"[{creation_id}] Generated default server name: {server_name}")
            
            # Update the creation session with the generated name
            update_creation_session(creation_id, "running", server_name)
            
        # Check if server name already exists and generate unique name if needed
        counter = 1
        base_name = server_name
        while server_name in data["servers"]:
            server_name = f"{base_name}{counter}"
            counter += 2
            creation_queues[creation_id].put({"message": f"Server name already exists, adjusted to: {server_name} <br>"})
            logger.info(f"[{creation_id}] Server name already exists, adjusted to: {server_name}")
        
        # Update status
        server_creation_status[creation_id]['server_name'] = server_name
        creation_queues[creation_id].put({"message": f"<br>Starting creation of server: {server_name} <br>"})
        logger.info(f"[{creation_id}] Starting server creation: {server_name}")
        
        # Check for port conflicts with other PZ servers
        while any(server["port"] == port for server in data["servers"].values()):
            port += 2
            creation_queues[creation_id].put({"message": f"Port conflict detected with another PZ server, adjusted to: {port} <br>"})
            logger.info(f"[{creation_id}] Port conflict detected, adjusted to: {port}")
        
        # Check if the port is in use by any process
        if is_port_in_use(port):
            old_port = port
            port = find_available_port(port)
            creation_queues[creation_id].put({"message": f"Port {old_port} is in use by another process, adjusted to: {port} <br>"})
            logger.info(f"[{creation_id}] Port {old_port} in use, adjusted to: {port}")
        
        # Same checks for query port
        while any(server["query_port"] == query_port for server in data["servers"].values()):
            query_port += 2
            creation_queues[creation_id].put({"message": f"Query port conflict detected with another PZ server, adjusted to: {query_port} <br>"})
            logger.info(f"[{creation_id}] Query port conflict detected, adjusted to: {query_port}")
        
        if is_port_in_use(query_port):
            old_query_port = query_port
            query_port = find_available_port(query_port)
            creation_queues[creation_id].put({"message": f"Query port {old_query_port} is in use by another process, adjusted to: {query_port} <br>"})
            logger.info(f"[{creation_id}] Query port {old_query_port} in use, adjusted to: {query_port}")
            
        # Now add the same checks for RCON port
        while any(server.get("rcon_port", 0) == rcon_port for server in data["servers"].values()):
            rcon_port += 2
            creation_queues[creation_id].put({"message": f"RCON port conflict detected with another PZ server, adjusted to: {rcon_port} <br>"})
            logger.info(f"[{creation_id}] RCON port conflict detected, adjusted to: {rcon_port}")
        
        if is_port_in_use(rcon_port):
            old_rcon_port = rcon_port
            rcon_port = find_available_port(rcon_port)
            creation_queues[creation_id].put({"message": f"RCON port {old_rcon_port} is in use by another process, adjusted to: {rcon_port} <br>"})
            logger.info(f"[{creation_id}] RCON port {old_rcon_port} in use, adjusted to: {rcon_port}")
        
        # Auto-fill admin password if empty
        if not admin_password.strip():
            admin_password = "shanmiru@Je"
            creation_queues[creation_id].put({"message": "Using default admin password <br>"})
            logger.info(f"[{creation_id}] Using default admin password")
        
        # Define paths once to reuse
        home_dir = f"/home/{server_name}"
        steamcmd_dir = f"{home_dir}/steamcmd"
        pzserver_dir = f"{home_dir}/PZServers"
        zomboid_dir = f"{home_dir}/Zomboid"
        server_config_dir = f"{zomboid_dir}/Server"
        server_ini_path = f"{server_config_dir}/{server_name}.ini"
        run_script_path = f"{pzserver_dir}/run-server.sh"
        
        logger.info(f"[{creation_id}] Paths defined - Home: {home_dir}, SteamCMD: {steamcmd_dir}, PZServer: {pzserver_dir}")

        rcon_password = secrets.token_urlsafe(10)

        data = load_servers()
        data["servers"][server_name] = {
            "name": server_name,
            "port": port,
            "query_port": query_port,
            "rcon_port": rcon_port,  # Add RCON port to server config
            "admin_password": admin_password,
            "server_password": server_password,
            "rcon_password": rcon_password,
            "status": "reserved",
            "marked": "reserved",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        save_servers(data)
        
        # Helper function to run command and stream output
        def run_command_with_output(command, shell=False, message_prefix=""):
            cmd_str = command if isinstance(command, str) else ' '.join(command)
            logger.info(f"[{creation_id}] Executing command: {cmd_str}")
            
            creation_queues[creation_id].put({"message": f"{message_prefix}  <br>"})
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                shell=shell
            )
            
            # Stream output in real-time
            for line in iter(process.stdout.readline, ''):
                if line.strip():
                    creation_queues[creation_id].put({"message": f"{line.strip()} <br>"})
                    logger.info(f"[{creation_id}] CMD OUTPUT: {line.strip()}")
            
            # Wait for process to complete and check return code
            process.wait()
            logger.info(f"[{creation_id}] Command completed with exit code: {process.returncode}")
            if process.returncode != 0:
                logger.error(f"[{creation_id}] Command failed with exit code: {process.returncode}")
                raise subprocess.CalledProcessError(process.returncode, command)
        
        # Execute server creation commands step by step with output
        creation_queues[creation_id].put({"message": f"Creating user '{server_name}'... <br>"})
        logger.info(f"[{creation_id}] Creating user: {server_name}")
        try:
            run_command_with_output(['sudo', 'adduser', server_name, '--gecos', '""', '--disabled-password'])
        except Exception as e:
            # Delete user if it exists despite the error
            run_command_with_output(['sudo', 'deluser', server_name, '--remove-home'])
            # Optionally: Log the error
            print(f"Error creating user: {e}")
        creation_queues[creation_id].put({"message": "User created successfully <br>"})
        
        creation_queues[creation_id].put({"message": "Setting password... <br>"})
        logger.info(f"[{creation_id}] Setting password for user: {server_name}")
        password_input = f"{server_name}:{admin_password}".encode()
        process = subprocess.Popen(["sudo", "chpasswd"], 
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input=password_input)
        if process.returncode != 0:
            error_msg = stderr.decode().strip()
            raise Exception(f"Password setting failed: {error_msg}")

        creation_queues[creation_id].put({"message": "Password set successfully <br>"})
        
        creation_queues[creation_id].put({"message": "Adding user to sudo group... <br>"})
        logger.info(f"[{creation_id}] Adding user to sudo group: {server_name}")
        run_command_with_output(['sudo', 'usermod', '-aG', 'sudo', server_name])
        creation_queues[creation_id].put({"message": "User added to sudo group <br>"})
        
        creation_queues[creation_id].put({"message": "Setting up server directories... <br>"})
        logger.info(f"[{creation_id}] Creating server directories")
        run_command_with_output(['sudo', '-u', server_name, 'bash', '-c', f'mkdir -p {steamcmd_dir}'])
        creation_queues[creation_id].put({"message": "Directories created successfully <br>"})
        
        # Install required 32-bit libraries first
        creation_queues[creation_id].put({"message": "Installing required 32-bit libraries... <br>"})
        logger.info(f"[{creation_id}] Installing required 32-bit libraries")
        try:
            run_command_with_output(['sudo', 'dpkg', '--add-architecture', 'i386'])
            run_command_with_output(['sudo', 'apt-get', 'update'])
            run_command_with_output(['sudo', 'apt-get', 'install', '-y', 'lib32gcc-s1', 'lib32stdc++6', 'libsdl2-2.0-0:i386'])
            creation_queues[creation_id].put({"message": "Required libraries installed successfully <br>"})
            logger.info(f"[{creation_id}] Required libraries installed successfully")
        except Exception as e:
            creation_queues[creation_id].put({"message": f"Warning: Could not install required libraries: {str(e)} <br>"})
            logger.warning(f"[{creation_id}] Could not install required libraries: {str(e)}")
        
        creation_queues[creation_id].put({"message": "Downloading SteamCMD... <br>"})
        logger.info(f"[{creation_id}] Downloading SteamCMD for server: {server_name}")
        run_command_with_output(['sudo', '-u', server_name, 'bash', '-c', 
                                    f'cd {steamcmd_dir} && wget https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz'])
        creation_queues[creation_id].put({"message": "SteamCMD downloaded successfully <br>"})
        
        creation_queues[creation_id].put({"message": "Extracting SteamCMD... <br>"})
        logger.info(f"[{creation_id}] Extracting SteamCMD")
        run_command_with_output(['sudo', '-u', server_name, 'bash', '-c', 
                            f'cd {steamcmd_dir} && tar -xvzf steamcmd_linux.tar.gz'])
        creation_queues[creation_id].put({"message": "SteamCMD extracted successfully <br>"})
        
        creation_queues[creation_id].put({"message": "Setting executable permissions for SteamCMD... <br>"})
        logger.info(f"[{creation_id}] Setting executable permissions for SteamCMD")
        run_command_with_output(['sudo', '-u', server_name, 'bash', '-c', 
                                f'chmod +x {steamcmd_dir}/steamcmd.sh'])
        creation_queues[creation_id].put({"message": "Permissions set successfully <br>"})

        # Create the PZServers directory if it doesn't exist
        logger.info(f"[{creation_id}] Creating PZServers directory")
        run_command_with_output(['sudo', '-u', server_name, 'bash', '-c', f'mkdir -p {pzserver_dir}'])
        
        # First run SteamCMD to install itself properly
        creation_queues[creation_id].put({"message": "Initializing SteamCMD (this might take a moment)... <br>"})
        logger.info(f"[{creation_id}] Initializing SteamCMD")
        try:
            run_command_with_output(['sudo', '-u', server_name, 'bash', '-c', 
                            f'cd {steamcmd_dir} && ./steamcmd.sh +force_install_dir {pzserver_dir} +login anonymous +app_update 380870 validate +quit'])
            creation_queues[creation_id].put({"message": "SteamCMD initialized successfully <br>"})
            logger.info(f"[{creation_id}] SteamCMD initialized successfully")
        except Exception as e:
            creation_queues[creation_id].put({"message": f"Warning: SteamCMD initialization error: {str(e)} <br>"})
            logger.warning(f"[{creation_id}] SteamCMD initialization error: {str(e)}")
        
        # Using exactly the same format that worked before, but with proper variable substitution
        creation_queues[creation_id].put({"message": "Installing Project Zomboid dedicated server (this might take several minutes)... <br>"})
        logger.info(f"[{creation_id}] Installing Project Zomboid dedicated server")
        logger.info(f"[{creation_id}] Running SteamCMD with command: cd {steamcmd_dir}")
        
        # Detailed inspection of steamcmd directory
        logger.info(f"[{creation_id}] Listing contents of steamcmd directory before installation")
        try:
            result = subprocess.run(['sudo', '-u', server_name, 'bash', '-c', f'ls -la {steamcmd_dir}'], 
                                capture_output=True, text=True)
            logger.info(f"[{creation_id}] SteamCMD directory contents: {result.stdout}")
            
            # Check if linux32 directory exists
            result = subprocess.run(['sudo', '-u', server_name, 'bash', '-c', f'ls -la {steamcmd_dir}/linux32 2>/dev/null || echo "linux32 directory not found"'], 
                                capture_output=True, text=True)
            logger.info(f"[{creation_id}] Linux32 directory check: {result.stdout}")
        except Exception as e:
            logger.warning(f"[{creation_id}] Error checking steamcmd directory: {str(e)}")
        
        try:
            run_command_with_output(['sudo', '-u', server_name, 'bash', '-c', 
                            f'cd {steamcmd_dir} && ./steamcmd.sh +force_install_dir ~/PZServers +login anonymous +app_update 380870 validate +quit'])
            logger.info(f"[{creation_id}] Project Zomboid server installed successfully")
        except Exception as e:
            logger.error(f"[{creation_id}] Error installing Project Zomboid server: {str(e)}")
            # Try alternative approach
            logger.info(f"[{creation_id}] Trying alternative installation approach")
            try:
                logger.info(f"[{creation_id}] Attempting direct linux32/steamcmd approach")
                run_command_with_output(['sudo', '-u', server_name, 'bash', '-c', 
                            f'cd {steamcmd_dir}/linux32 && ./steamcmd +force_install_dir ~/PZServers +login anonymous +app_update 380870 validate +quit'])
                logger.info(f"[{creation_id}] Alternative approach succeeded")
            except Exception as e2:
                logger.error(f"[{creation_id}] Alternative approach also failed: {str(e2)}")
                raise Exception(f"Could not install Project Zomboid server: {str(e)} / {str(e2)}")
        
        creation_queues[creation_id].put({"message": "Project Zomboid server installed successfully <br>"})
        
        creation_queues[creation_id].put({"message": "Creating server startup script... <br>"})
        logger.info(f"[{creation_id}] Creating server startup script")
        run_script = f"""#!/bin/bash
cd "$(dirname "$0")"
./start-server.sh -servername {server_name} -adminpassword {admin_password}
"""
        # Use sudo to write to the file with proper permissions
        run_command_with_output(['sudo', 'bash', '-c', f'echo "{run_script}" > {run_script_path}'])
        
        creation_queues[creation_id].put({"message": "Setting permissions for startup script... <br>"})
        logger.info(f"[{creation_id}] Setting permissions for startup script")
        run_command_with_output(['sudo', 'chmod', '+x', run_script_path])
        creation_queues[creation_id].put({"message": "Permissions set successfully <br>"})
        
        # Run the server for 10 seconds to generate initial configuration files
        creation_queues[creation_id].put({"message": "Starting server for 10 seconds to generate config files... <br>"})
        logger.info(f"[{creation_id}] Starting server briefly to generate config files: {server_name}")

        start_server(server_name)

        time.sleep(15)

        stop_server(server_name, brute_force=True)
        #server_process = subprocess.Popen(
        #        ['sudo', '-u', server_name, 'bash', '-c', f'cd {pzserver_dir} && ./run-server.sh'],
        #        stdout=subprocess.PIPE,
        #        stderr=subprocess.STDOUT
        #)

        #time.sleep(5)

        #if server_process.poll() is None:
        #    creation_queues[creation_id].put({"message": "Process is running <br>"})
        #    logger.info(f"[{creation_id}] Server process is running")
        #else:
        #    creation_queues[creation_id].put({"message": f"Process failed to start or exited immediately with code {server_process.returncode} <br>"})
        #    logger.warning(f"[{creation_id}] Server process failed to start or exited immediately with code {server_process.returncode}")
        
        # Wait for 10 seconds then terminate
        #time.sleep(10)
        #creation_queues[creation_id].put({"message": "Stopping server after config generation... <br>"})
        #logger.info(f"[{creation_id}] Stopping server after config generation")
        
        # Set open permissions for all server directories
        creation_queues[creation_id].put({"message": "Setting home_dir permissions <br>"})
        logger.info(f"[{creation_id}] Setting home_dir permissions")
        run_command_with_output(['sudo', 'chmod', '-R', '777', home_dir])
    
        creation_queues[creation_id].put({"message": "Setting run_script_path permissions <br>"})
        logger.info(f"[{creation_id}] Setting run_script_path permissions")
        run_command_with_output(['sudo', 'chmod', '777', run_script_path])

        # Ensure the Zomboid directory and server config directory exist
        logger.info(f"[{creation_id}] Creating server config directory if it doesn't exist")
        run_command_with_output(['sudo', '-u', server_name, 'bash', '-c', f'mkdir -p {server_config_dir}'])

        # Set proper permissions - make the config writable by anyone
        # Only try to set permissions if the file exists
        if os.path.exists(server_ini_path):
            creation_queues[creation_id].put({"message": "Setting server_ini_path permissions <br>"})
            logger.info(f"[{creation_id}] Setting server_ini_path permissions")
            run_command_with_output(['sudo', 'chmod', '777', server_ini_path])
        else:
            logger.warning(f"[{creation_id}] server.ini not found at {server_ini_path}, cannot set permissions")

        # Set open permissions for the Zomboid directory
        creation_queues[creation_id].put({"message": "Setting zomboid_dir permissions <br>"})
        logger.info(f"[{creation_id}] Setting zomboid_dir permissions")
        run_command_with_output(['sudo', 'chmod', '-R', '777', zomboid_dir])

        # Properly terminate the server and all related processes
        #try:
        #        # First try to kill the immediate process
        #        logger.info(f"[{creation_id}] Terminating server process")
        #        server_process.terminate()
        #        time.sleep(2)
                
                # If still running, forcefully kill it
        #        if server_process.poll() is None:
        #            logger.info(f"[{creation_id}] Process still running, sending KILL signal")
        #            server_process.kill()
        #            time.sleep(1)
                
                # Find and terminate all processes owned by the server user
        #        logger.info(f"[{creation_id}] Terminating all processes for user {server_name}")
        #        subprocess.run(['sudo', 'pkill', '-TERM', '-u', server_name], check=False)
        #        time.sleep(2)
        #        subprocess.run(['sudo', 'pkill', '-KILL', '-u', server_name], check=False)
                
         #       creation_queues[creation_id].put({"message": "Server stopped after config generation <br>"})
         #       logger.info(f"[{creation_id}] Server stopped after config generation")
                
                # Ensure server status is set to stopped in the configuration
          #      data = load_servers()
          #      if server_name in data["servers"]:
           #         data["servers"][server_name]["status"] = "stopped"
           #         # Remove any PID if it was stored
            #        if "pid" in data["servers"][server_name]:
            #            del data["servers"][server_name]["pid"]
            #        save_servers(data)
            #        logger.info(f"[{creation_id}] Updated server status to stopped in config")
                    
        #except Exception as e:
        #        creation_queues[creation_id].put({"message": f"Warning: Error while stopping server: {str(e)} <br>"})
        #        logger.warning(f"[{creation_id}] Error while stopping server {server_name}: {str(e)}")
        
        # Update the server.ini file with user-preferred ports
        creation_queues[creation_id].put({"message": f"Updating server configuration with correct ports... <br>"})
        logger.info(f"[{creation_id}] Updating server configuration with correct ports")

        # Check if server.ini exists
        if os.path.exists(server_ini_path):
            try:
                # Read the current ini file
                with open(server_ini_path, 'r') as f:
                    ini_content = f.read()
                
                logger.info(f"[{creation_id}] Current server.ini content: {ini_content}")
                
                # Update port settings using regex
                ini_content = re.sub(r'DefaultPort=\d+', f'DefaultPort={port}', ini_content)
                ini_content = re.sub(r'UDPPort=\d+', f'UDPPort={query_port}', ini_content)
                
                # Add or update RCON port
                if re.search(r'RCONPort=', ini_content):
                    ini_content = re.sub(r'RCONPort=\d+', f'RCONPort={rcon_port}', ini_content)
                else:
                    ini_content += f'\nRCONPort={rcon_port}'
                
                # Add or update server password if provided
                if server_password.strip():
                    if re.search(r'Password=', ini_content):
                        ini_content = re.sub(r'Password=.*', f'Password={server_password}', ini_content)
                    else:
                        ini_content += f'\nPassword={server_password}'
                
                # Generate and set RCON password
                if re.search(r'RCONPassword=', ini_content):
                    ini_content = re.sub(r'RCONPassword=.*', f'RCONPassword={rcon_password}', ini_content)
                else:
                    ini_content += f'\nRCONPassword={rcon_password}'
                
                logger.info(f"[{creation_id}] Updated server.ini content: {ini_content}")
                
                # Write the updated ini file
                with open(server_ini_path, 'w') as f:
                    f.write(ini_content)
                
                # Set proper permissions
                subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', server_ini_path], check=True)
                
                creation_queues[creation_id].put({"message": f"Server configuration updated with DefaultPort={port}, UDPPort={query_port}, and RCONPort={rcon_port} <br>"})
                logger.info(f"[{creation_id}] Server configuration updated with DefaultPort={port}, UDPPort={query_port}, and RCONPort={rcon_port}")
            except Exception as e:
                creation_queues[creation_id].put({"message": f"Warning: Error updating port configuration: {str(e)} <br>"})
                logger.warning(f"[{creation_id}] Error updating port configuration: {str(e)}")
        else:
            creation_queues[creation_id].put({"message": f"Warning: Could not find server.ini at {server_ini_path} <br>"})
            logger.warning(f"[{creation_id}] Could not find server.ini at {server_ini_path}")
            
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(server_ini_path), exist_ok=True)
                logger.info(f"[{creation_id}] Created directory {os.path.dirname(server_ini_path)}")
                
                # Create a basic ini file with the required ports
                # Generate RCON password if it wasn't set earlier
                if 'rcon_password' not in locals():
                    rcon_password = secrets.token_urlsafe(20)
                
                logger.info(f"[{creation_id}] Creating new server.ini with ports: {port}, {query_port}, {rcon_port}")
                with open(server_ini_path, 'w') as f:
                    f.write(f"DefaultPort={port}\nUDPPort={query_port}\nRCONPort={rcon_port}\n")
                    if server_password.strip():
                        f.write(f"Password={server_password}\n")
                    f.write(f"RCONPassword={rcon_password}\n")
                
                # Set proper permissions
                subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', server_ini_path], check=True)
                
                creation_queues[creation_id].put({"message": f"Created new server configuration with DefaultPort={port}, UDPPort={query_port}, and RCONPort={rcon_port} <br>"})
                logger.info(f"[{creation_id}] Created new server configuration with DefaultPort={port}, UDPPort={query_port}, and RCONPort={rcon_port}")
            except Exception as e:
                creation_queues[creation_id].put({"message": f"Warning: Error creating port configuration: {str(e)} <br>"})
                logger.warning(f"[{creation_id}] Error creating port configuration: {str(e)}")

        creation_queues[creation_id].put({"message": "Configuring firewall rules... <br>"})
        logger.info(f"[{creation_id}] Configuring firewall rules")
        # Configure firewall - allow all required ports
        subprocess.run(['sudo', 'ufw', 'allow', f'{port}/udp'], check=True)
        subprocess.run(['sudo', 'ufw', 'allow', f'{port}/tcp'], check=True)
        subprocess.run(['sudo', 'ufw', 'allow', f'{query_port}/udp'], check=True)
        subprocess.run(['sudo', 'ufw', 'allow', f'{query_port}/tcp'], check=True)
        # Add firewall rules for RCON port
        subprocess.run(['sudo', 'ufw', 'allow', f'{rcon_port}/udp'], check=True)
        subprocess.run(['sudo', 'ufw', 'allow', f'{rcon_port}/tcp'], check=True)
        subprocess.run(['sudo', 'ufw', 'reload'], check=True)
        creation_queues[creation_id].put({"message": "Firewall rules configured successfully <br>"})
        logger.info(f"[{creation_id}] Firewall rules configured for server {server_name} (ports: {port}, {query_port}, {rcon_port})")

        # Set open permissions for all server directories
        creation_queues[creation_id].put({"message": "Setting home_dir permissions <br>"})
        logger.info(f"[{creation_id}] Setting home_dir permissions")
        run_command_with_output(['sudo', 'chmod', '-R', '777', home_dir])
    
        creation_queues[creation_id].put({"message": "Setting run_script_path permissions <br>"})
        logger.info(f"[{creation_id}] Setting run_script_path permissions")
        run_command_with_output(['sudo', 'chmod', '777', run_script_path])

        # Set proper permissions - make the config writable by anyone
        if os.path.exists(server_ini_path):
            creation_queues[creation_id].put({"message": "Setting server_ini_path permissions <br>"})
            logger.info(f"[{creation_id}] Setting server_ini_path permissions")
            subprocess.run(['sudo', 'chmod', '777', server_ini_path], check=True)

        # Set open permissions for the Zomboid directory
        creation_queues[creation_id].put({"message": "Setting zomboid_dir permissions <br>"})
        logger.info(f"[{creation_id}] Setting zomboid_dir permissions")
        run_command_with_output(['sudo', 'chmod', '-R', '777', zomboid_dir])
        
        # Add server to config
        creation_queues[creation_id].put({"message": "Updating server configuration... <br>"})
        logger.info(f"[{creation_id}] Updating server configuration")
        # Reload server data to ensure we have the latest

        data = load_servers()
        data["servers"][server_name] = {
            "name": server_name,
            "port": port,
            "query_port": query_port,
            "rcon_port": rcon_port,  # Add RCON port to server config
            "admin_password": admin_password,
            "server_password": server_password,
            "rcon_password": rcon_password,
            "status": "stopped",
            "marked": "finish",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        save_servers(data)
        creation_queues[creation_id].put({"message": "Server configuration updated successfully <br>"})
        logger.info(f"[{creation_id}] Server configuration updated successfully")

        # Mark as complete
        update_creation_session(creation_id, "completed", server_name)
        server_creation_status[creation_id]['complete'] = True
        creation_queues[creation_id].put({"message": "Server created successfully! <br>", "complete": True})
        logger.info(f"[{creation_id}] Server {server_name} created successfully")
    except subprocess.CalledProcessError as e:
        data = load_servers()
        data["servers"][server_name] = {
            "name": server_name,
            "port": port,
            "query_port": query_port,
            "rcon_port": rcon_port,  # Add RCON port to server config
            "admin_password": admin_password,
            "server_password": server_password,
            "rcon_password": rcon_password,
            "status": "stopped",
            "marked": "finish",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        save_servers(data)
        error_message = f"Error creating server: {str(e)}"
        if hasattr(e, 'stdout') and e.stdout:
            error_message += f"\nOutput: {e.stdout}"
        if hasattr(e, 'stderr') and e.stderr:
            error_message += f"\nError: {e.stderr}"
        
        creation_queues[creation_id].put({"message": f"{error_message} <br>", "error": True, "complete": True})
        update_creation_session(creation_id, "failed")
        server_creation_status[creation_id]['error'] = True
        server_creation_status[creation_id]['error_message'] = error_message
        logger.error(f"[{creation_id}] Error creating server {server_name}: {error_message}")
    except Exception as e:
        data = load_servers()
        data["servers"][server_name] = {
            "name": server_name,
            "port": port,
            "query_port": query_port,
            "rcon_port": rcon_port,  # Add RCON port to server config
            "admin_password": admin_password,
            "server_password": server_password,
            "rcon_password": rcon_password,
            "status": "stopped",
            "marked": "finish",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        save_servers(data)
        error_details = traceback.format_exc()
        creation_queues[creation_id].put({"message": f"Error during server creation: {str(e)} <br>", "error": True})
        creation_queues[creation_id].put({"message": f"{error_details} <br>", "error": True})
        update_creation_session(creation_id, "failed")
        server_creation_status[creation_id]['error'] = True
        server_creation_status[creation_id]['error_message'] = str(e)
        logger.error(f"[{creation_id}] Exception during server creation: {str(e)}\n{error_details}")

def start_server(server_name):
    try:
        # Clear any previous status markers
        clear_server_status_markers(server_name)

        aws_setup = load_aws_cli_setup(server_name)
        
        # Update cron job if automatic backups are enabled
        if aws_setup.get('backup_enabled') == True:
            success = setup_backup_cron(server_name, f'/home/{server_name}/backup_script.sh', aws_setup)
        
        # Check current status
        current_status = get_server_status(server_name)
        if current_status in ["running", "loading", "started"]:
            logger.info(f"Server {server_name} is already running with status: {current_status}")
            return True, f"Server is already running (status: {current_status})"
        
        try:
            logs_path = f'/home/{server_name}/Zomboid/server-console.txt'
            webbase_log_path = f'/home/{server_name}/Zomboid/server-console-webbase.txt'
            open(logs_path, 'w').close()
            open(webbase_log_path, 'w').close()
        except Exception as e:
            logger.debug(f"Could not reset log files: {str(e)}")
            pass
        
        # Verify the server configuration file matches the server_configs.json
        try:
            # Load server config data
            data = load_servers()
            if server_name not in data["servers"]:
                logger.error(f"Server {server_name} not found in server_configs.json")
                return False, "Server configuration not found!"
                
            server_info = data["servers"][server_name]
            port = server_info.get("port")
            query_port = server_info.get("query_port")
            rcon_port = server_info.get("rcon_port")
            admin_password = server_info.get("admin_password")
            server_password = server_info.get("server_password", "")
            rcon_password = server_info.get("rcon_password")
            
            # Check the server.ini file
            server_ini_path = f"/home/{server_name}/Zomboid/Server/{server_name}.ini"
            
            if os.path.exists(server_ini_path):
                logger.info(f"Verifying server configuration for {server_name}")
                
                # Read the current ini file
                with open(server_ini_path, 'r') as f:
                    ini_content = f.read()
                
                # Check if configuration needs updating
                needs_update = False
                
                # Use regex to find current values
                current_port_match = re.search(r'DefaultPort=(\d+)', ini_content)
                current_query_port_match = re.search(r'UDPPort=(\d+)', ini_content)
                current_rcon_port_match = re.search(r'RCONPort=(\d+)', ini_content)
                current_password_match = re.search(r'Password=(.*?)(\n|$)', ini_content)
                current_rcon_password_match = re.search(r'RCONPassword=(.*?)(\n|$)', ini_content)
                
                # Extract current values if matches found
                current_port = int(current_port_match.group(1)) if current_port_match else None
                current_query_port = int(current_query_port_match.group(1)) if current_query_port_match else None
                current_rcon_port = int(current_rcon_port_match.group(1)) if current_rcon_port_match else None
                current_password = current_password_match.group(1) if current_password_match else ""
                current_rcon_password = current_rcon_password_match.group(1) if current_rcon_password_match else ""
                
                # Log the comparison
                logger.debug(f"Config comparison for {server_name}:")
                logger.debug(f"Port: {current_port} vs {port}")
                logger.debug(f"Query Port: {current_query_port} vs {query_port}")
                logger.debug(f"RCON Port: {current_rcon_port} vs {rcon_port}")
                logger.debug(f"Server Password: {current_password} vs {server_password}")
                
                # Check if values don't match
                if current_port != port or current_query_port != query_port or current_rcon_port != rcon_port or \
                   current_password != server_password or current_rcon_password != rcon_password:
                    logger.warning(f"Configuration mismatch detected for server {server_name}, updating...")
                    needs_update = True
                
                if needs_update:
                    # Update port settings using regex
                    ini_content = re.sub(r'DefaultPort=\d+', f'DefaultPort={port}', ini_content)
                    ini_content = re.sub(r'UDPPort=\d+', f'UDPPort={query_port}', ini_content)
                    
                    # Add or update RCON port
                    if re.search(r'RCONPort=', ini_content):
                        ini_content = re.sub(r'RCONPort=\d+', f'RCONPort={rcon_port}', ini_content)
                    else:
                        ini_content += f'\nRCONPort={rcon_port}'
                    
                    # Add or update server password if provided
                    if server_password.strip():
                        if re.search(r'Password=', ini_content):
                            ini_content = re.sub(r'Password=.*', f'Password={server_password}', ini_content)
                        else:
                            ini_content += f'\nPassword={server_password}'
                    
                    # Add or update RCON password
                    if re.search(r'RCONPassword=', ini_content):
                        ini_content = re.sub(r'RCONPassword=.*', f'RCONPassword={rcon_password}', ini_content)
                    else:
                        ini_content += f'\nRCONPassword={rcon_password}'
                    
                    # Write the updated ini file
                    with open(server_ini_path, 'w') as f:
                        f.write(ini_content)
                    
                    # Set proper permissions
                    subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', server_ini_path], check=True)
                    subprocess.run(['sudo', 'chmod', '777', server_ini_path], check=True)
                    
                    logger.info(f"Updated server configuration for {server_name}")
            else:
                logger.warning(f"Server.ini not found at {server_ini_path}, will be created on first run")
        except Exception as config_error:
            logger.error(f"Error verifying/updating server configuration: {str(config_error)}")

        # Check for spawn region files and copy them if they don't exist
        try:
            # Check if the spawn region and spawn points files exist
            server_dir = f"/home/{server_name}/Zomboid/Server"
            spawn_regions_file = f"{server_dir}/{server_name}_spawnregions.lua"
            spawn_points_file = f"{server_dir}/{server_name}_spawnpoints.lua"
            
            # Source files in the pz_manager directory
            source_dir = os.path.join(os.path.dirname(__file__), "save", "lua")
            source_regions = f"{source_dir}/_spawnregions.lua"
            source_points = f"{source_dir}/_spawnpoints.lua"

            # If spawn regions file does not exist, copy it from the source directory
            if not os.path.exists(spawn_regions_file):
                logger.info(f"Copying spawn regions file for {server_name}")
                shutil.copy2(source_regions, spawn_regions_file)
                subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', spawn_regions_file], check=True)
                subprocess.run(['sudo', 'chmod', '666', spawn_regions_file], check=True)
                logger.info(f"Successfully copied spawn regions file for {server_name}")
                
                # Rename the copied spawn regions file
                new_spawn_regions_file = os.path.join(os.path.dirname(spawn_regions_file), f"{server_name}_spawnregions.lua")
                os.rename(spawn_regions_file, new_spawn_regions_file)
                logger.info(f"Renamed copied spawn regions file to {new_spawn_regions_file}")

            # If spawn points file does not exist, copy it from the source directory
            if not os.path.exists(spawn_points_file):
                logger.info(f"Copying spawn points file for {server_name}")
                shutil.copy2(source_points, spawn_points_file)
                subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', spawn_points_file], check=True)
                subprocess.run(['sudo', 'chmod', '666', spawn_points_file], check=True)
                logger.info(f"Successfully copied spawn points file for {server_name}")
                
                # Rename the copied spawn points file
                new_spawn_points_file = os.path.join(os.path.dirname(spawn_points_file), f"{server_name}_spawnpoints.lua")
                os.rename(spawn_points_file, new_spawn_points_file)
                logger.info(f"Renamed copied spawn points file to {new_spawn_points_file}")
            
        except Exception as spawn_files_error:
            logger.error(f"Error copying spawn files for {server_name}: {str(spawn_files_error)}")
            # Continue anyway - not critical for server start
        
        # Check if a screen session already exists for this specific server

        check_cmd = f"screen -list | grep {server_name}"
        result = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode == 0:
            if "(Dead" in result.stdout:
                check_cmd = ["screen", "-wipe"]
                subprocess.run(check_cmd, capture_output=True, text=True, check=False)


            time.sleep(2)

            logger.warning(f"Screen session for {server_name} already exists")
            rerun_cmd = f"screen -S {server_name} -X stuff 'cd -\n'"
            subprocess.run(rerun_cmd, shell=True, check=True)
            # Reconnect to existing screen, switch user and start server
            restart_cmd = f"screen -S {server_name} -X stuff 'cd PZServers && ./run-server.sh\n'"
            subprocess.run(restart_cmd, shell=True, check=True)
                
            # Update server status
            data = load_servers()
            data["servers"][server_name]["status"] = "started"
            save_servers(data)
                
            logger.info(f"Reconnected to existing screen session for {server_name} and started server")
            return True, "Reconnected to existing screen session and started server!"
        
        log_path = f'/home/{server_name}/Zomboid/server-console.txt'
        
        # Start server in a new screen session with proper user switching
        start_cmd = f"screen -L -Logfile {log_path} -dmS {server_name} bash -c 'sudo su - {server_name}'"
        subprocess.run(start_cmd, shell=True, check=True)
        time.sleep(2)
        
        # Send command to the specific server's screen session
        run_cmd = f"screen -S {server_name} -X stuff 'cd PZServers && ./run-server.sh\n'"
        subprocess.run(run_cmd, shell=True, check=True)
        
        # Wait a moment to allow the server to start
        time.sleep(3)
        
        # Verify screen session exists
        verify_cmd = f"screen -list | grep {server_name}"
        verify_result = subprocess.run(verify_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if verify_result.returncode != 0:
            raise Exception("Failed to create screen session")
        
        # Update server status
        data = load_servers()
        data["servers"][server_name]["status"] = "started"
        save_servers(data)
        
        logger.info(f"Server {server_name} started successfully in screen session")
        return True, "Server started successfully in screen session!"
    except Exception as e:
        logger.error(f"Error starting server {server_name}: {str(e)}", exc_info=True)
        return False, f"Error starting server: {str(e)}"

def stop_server(server_name, brute_force=False):
    try:

        if brute_force:

            try:
                logs_path = f'/home/{server_name}/Zomboid/server-console.txt'
                webbase_log_path = f'/home/{server_name}/Zomboid/server-console-webbase.txt'
                open(logs_path, 'w').close()
                open(webbase_log_path, 'w').close()
            except Exception as e:
                logger.debug(f"Could not reset log files: {str(e)}")
                pass

            # Set the stopping marker
            set_server_status_marker(server_name, "stopping")
            
            # Check if screen session exists for this specific server
            check_cmd = f"screen -list | grep '{server_name}'"
            result = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if result.returncode != 0:
                logger.warning(f"No screen session found for {server_name}")
                # Clean up marker
                clear_server_status_markers(server_name)
                return False, "Server not running!"
            
            # Find all processes related to the server
            logger.info(f"Finding all processes related to server {server_name}")
            find_cmd = f"ps aux | grep '{server_name}'"
            ps_result = subprocess.run(find_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Process each line and kill the processes
            killed_pids = []
            for line in ps_result.stdout.decode('utf-8').strip().split('\n'):
                # Skip grep process itself
                if f"grep '{server_name}'" in line:
                    continue
                    
                # Process the line to extract PID
                parts = line.split()
                if len(parts) > 1:
                    try:
                        pid = int(parts[1])
                        # Kill the process
                        kill_cmd = f"kill -9 {pid}"
                        subprocess.run(kill_cmd, shell=True, check=False)
                        killed_pids.append(pid)
                        logger.debug(f"Killed process with PID: {pid}")
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Could not extract PID from line: {line}, error: {str(e)}")
            
            # Get the actual screen session ID (which may include hostname)
            session_id = None
            for line in result.stdout.decode('utf-8').strip().split('\n'):
                if server_name in line:
                    parts = line.strip().split('\t')
                    if len(parts) > 0:
                        session_id = parts[0].strip()
                        logger.debug(f"Found screen session ID: {session_id}")
                        break
            
            if not session_id:
                logger.warning(f"Could not parse screen session ID for {server_name}")
                # Clean up marker
                clear_server_status_markers(server_name)
                return False, "Could not identify server screen session!"
            
            # Forcefully kill the screen session
            logger.info(f"Forcefully killing screen session for server {server_name}")
            kill_cmd = f"screen -S {session_id} -X quit"
            subprocess.run(kill_cmd, shell=True, check=True)
            
            # Wait a few seconds then clean up any dead screens
            logger.info("Waiting a few seconds before cleaning up dead screen sessions")
            time.sleep(3)
            subprocess.run("screen -wipe", shell=True, check=False)
            
            # Update server status and clean up markers
            data = load_servers()
            data["servers"][server_name] = {
                "status": "stopped"
                }
            save_servers(data)
            
            # Remove backup cron job
            remove_backup_cron(server_name)
            
            # Clear markers
            clear_server_status_markers(server_name)
            
            logger.info(f"Server {server_name} forcefully terminated. Killed {len(killed_pids)} processes: {killed_pids}")
            return True, f"Server forcefully terminated! Killed {len(killed_pids)} processes."
            
            

        # Set the stopping marker
        set_server_status_marker(server_name, "stopping")   

        remove_backup_cron(server_name)
        
        # Check if screen session exists for this specific server
        check_cmd = f"screen -list | grep '{server_name}'"
        result = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            logger.warning(f"No screen session found for {server_name}")
            # Clean up marker
            clear_server_status_markers(server_name)
            return False, "Server not running!"
        
        # Get the actual screen session ID (which may include hostname)
        session_id = None
        for line in result.stdout.decode('utf-8').strip().split('\n'):
            if server_name in line:
                parts = line.strip().split('\t')
                if len(parts) > 0:
                    session_id = parts[0].strip()
                    logger.debug(f"Found screen session ID: {session_id}")
                    break
        
        if not session_id:
            logger.warning(f"Could not parse screen session ID for {server_name}")
            # Clean up marker
            clear_server_status_markers(server_name)
            return False, "Could not identify server screen session!"

        save_cmd = f"screen -S {session_id} -X stuff '\n'"
        subprocess.run(save_cmd, shell=True, check=True)
        
        # Send 'save' command to the specific server's screen session
        logger.info(f"Sending save command to server {server_name}")
        save_cmd = f"screen -S {session_id} -X stuff 'save\n'"
        subprocess.run(save_cmd, shell=True, check=True)
        
        # Wait for save to complete
        logger.info(f"Waiting for save to complete on server {server_name}")
        time.sleep(5)

        save_cmd = f"screen -S {session_id} -X stuff 'quit\n'"
        subprocess.run(save_cmd, shell=True, check=True)

        time.sleep(15)
        
        # Update server status and clean up markers
        data = load_servers()
        data["servers"][server_name]["status"] = "stopped"
        save_servers(data)
        
        # Clear markers
        clear_server_status_markers(server_name)
        
        logger.info(f"Server {server_name} saved successfully (screen session preserved)")
        return True, "Server saved successfully!"
    except Exception as e:
        # Clear markers on error
        clear_server_status_markers(server_name)
        logger.error(f"Error stopping server {server_name}: {str(e)}", exc_info=True)
        return False, f"Error saving server: {str(e)}"
    
def restart_server(server_name):
    try:
        # Set restarting marker
        set_server_status_marker(server_name, "restarting")
        
        logger.info(f"Restarting server: {server_name}")
        # First stop the server
        stop_success, stop_message = stop_server(server_name)
        if not stop_success:
            logger.warning(f"Failed to stop server: {stop_message}")
            # Clear markers
            clear_server_status_markers(server_name)
            return False, f"Failed to stop server: {stop_message}"
        
        time.sleep(5)
        start_success, start_message = start_server(server_name)
        if not start_success:
            logger.warning(f"Failed to start server after stopping: {start_message}")
            # Clear markers
            clear_server_status_markers(server_name)
            return False, f"Failed to start server after stopping: {start_message}"
        
        # Clear restarting marker
        clear_server_status_markers(server_name)
        
        logger.info(f"Server {server_name} restarted successfully")
        return True, "Server restarted successfully!"
    except Exception as e:
        # Clear markers on error
        clear_server_status_markers(server_name)
        logger.error(f"Unexpected error during restart of server {server_name}: {str(e)}")
        return False, f"Unexpected error during restart: {str(e)}"

def delete_server(server_name):
    try:
        logger.info(f"[DELETE_SERVER] Starting deletion process for server: {server_name}")

        remove_backup_cron(server_name)

        config_file = f'aws_cli_setup_{server_name}.json'
        if os.path.exists(config_file):
            os.remove(config_file)
     
        # First check if server is running in a screen session
        logger.info(f"[DELETE_SERVER] Checking for active screen sessions for {server_name}")
        screen_check = subprocess.run(['screen', '-list'], capture_output=True, text=True)
        
        if server_name in screen_check.stdout:
            logger.info(f"[DELETE_SERVER] Found active screen session for {server_name}, attempting to terminate")
            
            # Try to kill the screen session as the server user
            logger.debug(f"[DELETE_SERVER] Attempting to quit screen session as user {server_name}")
            subprocess.run(['sudo', '-u', server_name, 'screen', '-S', server_name, '-X', 'quit'], check=False)
            
            # Wait a moment to let the process terminate
            logger.debug(f"[DELETE_SERVER] Waiting for screen session to terminate")
            time.sleep(2)
            
            # Check if it's still running
            logger.debug(f"[DELETE_SERVER] Checking if screen session is still active")
            screen_check = subprocess.run(['screen', '-list'], capture_output=True, text=True)
            
            if server_name in screen_check.stdout:
                logger.warning(f"[DELETE_SERVER] Screen session for {server_name} still active, attempting more aggressive termination")
                
                # Get the actual screen session ID (which may include hostname)
                session_id = None
                for line in screen_check.stdout.strip().split('\n'):
                    if server_name in line:
                        parts = line.strip().split('\t')
                        if len(parts) > 0:
                            session_id = parts[0].strip()
                            logger.debug(f"[DELETE_SERVER] Found screen session ID: {session_id}")
                            break
                
                if session_id:
                    # Try a more forceful approach with the full session ID
                    logger.debug(f"[DELETE_SERVER] Attempting to forcefully quit screen session with ID: {session_id}")
                    subprocess.run(['sudo', 'screen', '-S', session_id, '-X', 'quit'], check=False)
                
                # One last try with pkill
                logger.debug(f"[DELETE_SERVER] Using pkill as a last resort to terminate screen session")
                subprocess.run(['sudo', 'pkill', '-f', f"SCREEN.*{server_name}"], check=False)
                logger.debug(f"[DELETE_SERVER] Waiting after pkill attempt")
                time.sleep(2)
                
                # Final verification
                final_check = subprocess.run(['screen', '-list'], capture_output=True, text=True)
                if server_name in final_check.stdout:
                    logger.warning(f"[DELETE_SERVER] Screen session for {server_name} could not be terminated completely")
                else:
                    logger.info(f"[DELETE_SERVER] Screen session for {server_name} successfully terminated")
        else:
            logger.info(f"[DELETE_SERVER] No active screen sessions found for {server_name}")
        
        # Find any remaining processes owned by the user
        logger.info(f"[DELETE_SERVER] Checking for any remaining processes owned by {server_name}")
        process_check = subprocess.run(['ps', '-u', server_name, '-o', 'pid='], capture_output=True, text=True)
        
        if process_check.stdout.strip():
            logger.warning(f"[DELETE_SERVER] Found remaining processes owned by {server_name}, attempting to terminate")
            process_count = 0
            
            # Kill any remaining processes
            for pid in process_check.stdout.strip().split('\n'):
                if pid.strip():
                    process_count += 1
                    logger.debug(f"[DELETE_SERVER] Killing process with PID: {pid.strip()}")
                    kill_result = subprocess.run(['sudo', 'kill', '-9', pid.strip()], check=False, capture_output=True, text=True)
                    if kill_result.returncode != 0:
                        logger.warning(f"[DELETE_SERVER] Failed to kill process {pid.strip()}: {kill_result.stderr}")
            
            logger.info(f"[DELETE_SERVER] Attempted to kill {process_count} processes for user {server_name}")
            
            # Wait a moment for processes to terminate
            logger.debug(f"[DELETE_SERVER] Waiting for processes to terminate")
            time.sleep(3)
            
            # Verify all processes are gone
            final_process_check = subprocess.run(['ps', '-u', server_name, '-o', 'pid='], capture_output=True, text=True)
            if final_process_check.stdout.strip():
                remaining_count = len(final_process_check.stdout.strip().split('\n'))
                logger.warning(f"[DELETE_SERVER] {remaining_count} processes still remain for user {server_name}")
            else:
                logger.info(f"[DELETE_SERVER] All processes for user {server_name} successfully terminated")
        else:
            logger.info(f"[DELETE_SERVER] No running processes found for user {server_name}")
        
        # Now remove the user and their home directory
        logger.info(f"[DELETE_SERVER] Removing user account and home directory for {server_name}")
        try:
            userdel_result = subprocess.run(['sudo', 'userdel', '-r', server_name], capture_output=True, text=True, check=True)
            logger.info(f"[DELETE_SERVER] User {server_name} and home directory successfully removed")
        except Exception as e:
            logger.warning(f"[DELETE_SERVER] Error during userdel for {server_name}: {str(e)}")
            # Check if home directory still exists
            if os.path.exists(f"/home/{server_name}"):
                logger.warning(f"[DELETE_SERVER] Home directory for {server_name} still exists, attempting manual removal")
                try:
                    subprocess.run(['sudo', 'rm', '-rf', f"/home/{server_name}"], check=False)
                    if not os.path.exists(f"/home/{server_name}"):
                        logger.info(f"[DELETE_SERVER] Home directory for {server_name} manually removed")
                    else:
                        logger.error(f"[DELETE_SERVER] Failed to manually remove home directory for {server_name}")
                except Exception as rm_error:
                    logger.error(f"[DELETE_SERVER] Error removing home directory: {str(rm_error)}")

        # Remove server from config
        logger.info(f"[DELETE_SERVER] Removing server {server_name} from configuration")
        data = load_servers()
        if server_name in data["servers"]:
            port = data["servers"][server_name]["port"]
            query_port = data["servers"][server_name]["query_port"]
            rcon_port = data["servers"][server_name].get("rcon_port", 27015)  # Get RCON port, default to 27015 if not set
            logger.debug(f"[DELETE_SERVER] Found ports for server {server_name}: Main={port}, Query={query_port}, RCON={rcon_port}")
            
            # Remove firewall rules
            logger.info(f"[DELETE_SERVER] Removing firewall rules for server {server_name}")
            try:
                # Remove Game port rules
                logger.debug(f"[DELETE_SERVER] Removing main port firewall rules: {port}/udp and {port}/tcp")
                subprocess.run(['sudo', 'ufw', 'delete', 'allow', f'{port}/udp'], check=False)
                subprocess.run(['sudo', 'ufw', 'delete', 'allow', f'{port}/tcp'], check=False)
                
                # Remove Query port rules
                logger.debug(f"[DELETE_SERVER] Removing query port firewall rules: {query_port}/udp and {query_port}/tcp")
                subprocess.run(['sudo', 'ufw', 'delete', 'allow', f'{query_port}/udp'], check=False)
                subprocess.run(['sudo', 'ufw', 'delete', 'allow', f'{query_port}/tcp'], check=False)
                
                # Remove RCON port rules
                logger.debug(f"[DELETE_SERVER] Removing RCON port firewall rules: {rcon_port}/udp and {rcon_port}/tcp")
                subprocess.run(['sudo', 'ufw', 'delete', 'allow', f'{rcon_port}/udp'], check=False)
                subprocess.run(['sudo', 'ufw', 'delete', 'allow', f'{rcon_port}/tcp'], check=False)
                
                # Reload firewall
                logger.debug(f"[DELETE_SERVER] Reloading firewall configuration")
                subprocess.run(['sudo', 'ufw', 'reload'], check=False)
                logger.info(f"[DELETE_SERVER] Successfully removed firewall rules for server {server_name}")
            except Exception as e:
                logger.warning(f"[DELETE_SERVER] Error removing firewall rules: {str(e)}")
                # Ignore firewall rule deletion issues
            
            # Remove server from configuration
            logger.debug(f"[DELETE_SERVER] Deleting server {server_name} from configuration data")
            del data["servers"][server_name]
            save_servers(data)
            logger.info(f"[DELETE_SERVER] Server {server_name} successfully removed from configuration")
        else:
            logger.warning(f"[DELETE_SERVER] Server {server_name} not found in configuration data")
        
        # Check for and remove systemd service file if it exists
        service_path = f"/etc/systemd/system/pzserver-{server_name}.service"
        if os.path.exists(service_path):
            logger.info(f"[DELETE_SERVER] Removing systemd service file: {service_path}")
            try:
                subprocess.run(['sudo', 'systemctl', 'stop', f'pzserver-{server_name}'], check=False)
                subprocess.run(['sudo', 'systemctl', 'disable', f'pzserver-{server_name}'], check=False)
                subprocess.run(['sudo', 'rm', service_path], check=True)
                subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
                logger.info(f"[DELETE_SERVER] Successfully removed systemd service for {server_name}")
            except Exception as e:
                logger.warning(f"[DELETE_SERVER] Error removing systemd service: {str(e)}")
        
        logger.info(f"[DELETE_SERVER] Server {server_name} deletion process completed successfully")
        return True, "Server deleted successfully!"
    except subprocess.CalledProcessError as e:
        error_msg = f"Error executing command: {str(e)}"
        if hasattr(e, 'stderr') and e.stderr:
            error_msg += f" - stderr: {e.stderr}"
        logger.error(f"[DELETE_SERVER] {error_msg}")
        return False, f"Error deleting server: {str(e)}"
    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"[DELETE_SERVER] Unexpected error during server {server_name} deletion: {str(e)}\n{tb}")
        return False, f"Unexpected error during server deletion: {str(e)}"

def get_server_status(server_name):
    """
    Enhanced server status detection with more detailed states:
    - started: Initial startup phase
    - loading: Loading game assets and world
    - running: Fully running and accepting connections
    - restarting: Server is in the process of restarting
    - stopping: Server is in the process of shutting down
    - stopped: Server is not running
    - failed: Server failed to start or crashed
    """
    try:
        data = load_servers()
        
        # Check if the server is marked as reserved (creating)
        if server_name in data["servers"] and data["servers"][server_name].get("marked") == "reserved":
            return "creating"

        # First check if a restart or stop operation is in progress
        # Check for a marker file that indicates a restart is in progress
        restart_marker = f'/tmp/pzserver-{server_name}-restarting'
        stopping_marker = f'/tmp/pzserver-{server_name}-stopping'
        
        if os.path.exists(restart_marker):
            return "restarting"
        
        if os.path.exists(stopping_marker):
            return "stopping"
            
        # Check for a screen session with this server's name
        screen_check = subprocess.run(
            ['screen', '-list'], 
            capture_output=True, text=True
        )
        screen_running = server_name in screen_check.stdout
        
        # Check specifically for Java processes for this server
        java_check = subprocess.run(
            ['pgrep', '-f', f'java.*{server_name}'], 
            capture_output=True, text=True
        )
        
        # Also check for the start-server.sh process for this server
        server_process = subprocess.run(
            ['pgrep', '-f', f'start-server.sh.*{server_name}'],
            capture_output=True, text=True
        )
        
        # Determine if any server processes are running
        process_running = bool(java_check.stdout.strip() or server_process.stdout.strip())
        
        # If no processes are running, server is stopped
        if not screen_running and not process_running:
            return "stopped"
        
        # CHANGE HERE: If the server was previously running and processes are still active,
        # keep it as running rather than downgrading to "started"
        if data["servers"][server_name].get("status") == "running" and process_running:
            return "running"
            
        # Check server logs to determine exact status
        logs_path = f'/home/{server_name}/Zomboid/server-console.txt'
        
        # Check if the log file exists
        if not os.path.exists(logs_path):
            # No logs but process is running - assume it's just started
            return "started" if process_running else "stopped"
            
        # Get the last 50 lines of the log file to determine status
        log_check = subprocess.run(
            ['tail', '-n', '50', logs_path],
            capture_output=True, text=True
        )
        log_content = log_check.stdout
        
        # Check for common error patterns that indicate failure
        error_patterns = [
            "Server initialization failed"
        ]
        
        if any(pattern in log_content for pattern in error_patterns) and not "*** SERVER STARTED ****" in log_content:
            return "failed"
            
        # Check if server has fully started
        if "*** SERVER STARTED ****" in log_content:
            return "running"
            
        # Check if server is in loading phase
        loading_patterns = [
            "LOADING ASSETS: START", "Loading world", "Initialising Server Systems"
        ]
        
        if any(pattern in log_content for pattern in loading_patterns):
            return "loading"
            
        # Check if server is in initial startup phase
        startup_patterns = [
            "Loading networking libraries", "Loading steam_api", "LoggerManager.init"
        ]
        
        if any(pattern in log_content for pattern in startup_patterns):
            return "started"
        
        # If we have processes running but couldn't determine the state from logs,
        # default to "started" since it's likely in an early phase
        if process_running:
            return "started"
        
        # Default fallback
        return "stopped"
        
    except Exception as e:
        logger.error(f"Error checking server status for {server_name}: {str(e)}")
        print(f"Error checking server status: {e}")
        return "unknown"

def get_cpu_temperature():
    """Get CPU temperature from various sources"""
    temperature = 0
    try:
        # Try psutil first
        temps = psutil.sensors_temperatures()
        if temps:
            for key in ['coretemp', 'k10temp', 'scpi_sensors', 'cpu_thermal']:
                if key in temps and temps[key]:
                    temperature = round(temps[key][0].current)
                    return temperature
                    
        # Fall back to reading thermal files
        for i in range(5):
            thermal_file = f"/sys/class/thermal/thermal_zone{i}/temp"
            if os.path.exists(thermal_file):
                with open(thermal_file, 'r') as f:
                    temp = int(f.read().strip()) / 1000
                    if temp > 0 and temp < 150:
                        return round(temp)
    except Exception:
        pass
        
    # Default value if we couldn't get temperature
    return 0

# File Management
@app.route('/api/server/<server_name>/files')
@login_required
def api_list_files(server_name):
    """API endpoint to list files and folders in a directory"""
    path = request.args.get('path', f'/home/{server_name}/')
    
    # Security check - ensure path is within server's home directory
    if not path.startswith(f'/home/{server_name}/'):
        logger.warning(f"Security: Attempted file access outside server directory by user {session.get('username')}")
        return jsonify({"success": False, "message": "Security violation: Access denied"}), 403
    
    try:
        # Check if directory exists
        if not os.path.exists(path) or not os.path.isdir(path):
            return jsonify({"success": False, "message": "Directory not found"}), 404
        
        # List contents
        contents = {"folders": [], "files": []}
        
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            
            # Skip hidden files and directories if not explicitly requested
            if item.startswith('.') and not request.args.get('show_hidden', False):
                continue
                
            if os.path.isdir(item_path):
                contents["folders"].append(item)
            else:
                contents["files"].append(item)
                
        # Sort alphabetically
        contents["folders"].sort()
        contents["files"].sort()
        
        logger.debug(f"User {session.get('username')} listed files in {path}")
        return jsonify({"success": True, "contents": contents})
    except Exception as e:
        logger.error(f"Error listing files in {path}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/<server_name>/file', methods=['GET'])
@login_required
def api_get_file(server_name):
    """API endpoint to get file contents"""
    path = request.args.get('path')
    
    if not path:
        return jsonify({"success": False, "message": "Path parameter is required"}), 400
    
    # Security check
    if not path.startswith(f'/home/{server_name}/'):
        logger.warning(f"Security: Attempted file access outside server directory by user {session.get('username')}")
        return jsonify({"success": False, "message": "Security violation: Access denied"}), 403
    
    try:
        # Check if file exists
        if not os.path.exists(path) or os.path.isdir(path):
            return jsonify({"success": False, "message": "File not found"}), 404
        
        # Check if file is binary (to avoid crashing on binary files)
        if is_binary_file(path):
            return jsonify({"success": False, "message": "Cannot read binary file"}), 415
        
        # Read file
        with open(path, 'r', errors='replace') as f:
            content = f.read()
        
        logger.debug(f"User {session.get('username')} read file {path}")
        return jsonify({"success": True, "content": content})
    except Exception as e:
        logger.error(f"Error reading file {path}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/<server_name>/upload', methods=['POST'])
@login_required
@admin_required
def api_upload_files(server_name):
    """API endpoint to upload files"""
    path = request.form.get('path')
    files = request.files.getlist('files')
    
    if not path:
        return jsonify({"success": False, "message": "Path parameter is required"}), 400
    
    if not files:
        return jsonify({"success": False, "message": "No files uploaded"}), 400
    
    # Security check
    if not path.startswith(f'/home/{server_name}/'):
        logger.warning(f"Security: Attempted file upload outside server directory by user {session.get('username')}")
        return jsonify({"success": False, "message": "Security violation: Access denied"}), 403
    
    try:
        # Ensure directory exists
        os.makedirs(path, exist_ok=True)
        
        uploaded_files = []
        
        for file in files:
            if file and file.filename:
                # Secure filename to prevent path traversal
                filename = secure_filename(file.filename)
                filepath = os.path.join(path, filename)
                
                # Save the file
                file.save(filepath)
                
                # Set proper ownership
                subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', filepath], check=True)
                
                uploaded_files.append(filename)
        
        logger.info(f"User {session.get('username')} uploaded {len(uploaded_files)} files to {path}")
        return jsonify({"success": True, "files": uploaded_files})
    except Exception as e:
        logger.error(f"Error uploading files to {path}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/<server_name>/file', methods=['POST'])
@login_required
@admin_required
def api_save_file(server_name):
    """API endpoint to save file content"""
    data = request.json
    path = data.get('path')
    content = data.get('content', '')
    
    if not path:
        return jsonify({"success": False, "message": "Path parameter is required"}), 400
    
    # Security check
    if not path.startswith(f'/home/{server_name}/'):
        logger.warning(f"Security: Attempted file write outside server directory by user {session.get('username')}")
        return jsonify({"success": False, "message": "Security violation: Access denied"}), 403
    
    try:
        # Create parent directories if they don't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Write file
        with open(path, 'w') as f:
            f.write(content)
        
        # Set proper ownership
        subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', path], check=True)
        
        logger.info(f"User {session.get('username')} saved file {path}")
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Error saving file {path}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/<server_name>/folder', methods=['POST'])
@login_required
@admin_required
def api_create_folder(server_name):
    """API endpoint to create a folder"""
    data = request.json
    path = data.get('path')
    
    if not path:
        return jsonify({"success": False, "message": "Path parameter is required"}), 400
    
    # Security check
    if not path.startswith(f'/home/{server_name}/'):
        logger.warning(f"Security: Attempted folder creation outside server directory by user {session.get('username')}")
        return jsonify({"success": False, "message": "Security violation: Access denied"}), 403
    
    try:
        # Create folder
        os.makedirs(path, exist_ok=True)
        
        # Set proper ownership
        subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', path], check=True)
        
        logger.info(f"User {session.get('username')} created folder {path}")
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Error creating folder {path}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/<server_name>/file', methods=['DELETE'])
@login_required
@admin_required
def api_delete_file(server_name):
    """API endpoint to delete a file"""
    data = request.json
    path = data.get('path')
    
    if not path:
        return jsonify({"success": False, "message": "Path parameter is required"}), 400
    
    # Security check
    if not path.startswith(f'/home/{server_name}/'):
        logger.warning(f"Security: Attempted file deletion outside server directory by user {session.get('username')}")
        return jsonify({"success": False, "message": "Security violation: Access denied"}), 403
    
    try:
        # Check if file exists
        if not os.path.exists(path) or os.path.isdir(path):
            return jsonify({"success": False, "message": "File not found"}), 404
        
        # Delete file
        os.remove(path)
        
        logger.info(f"User {session.get('username')} deleted file {path}")
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Error deleting file {path}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/<server_name>/folder', methods=['DELETE'])
@login_required
@admin_required
def api_delete_folder(server_name):
    """API endpoint to delete a folder"""
    data = request.json
    path = data.get('path')
    
    if not path:
        return jsonify({"success": False, "message": "Path parameter is required"}), 400
    
    # Security check
    if not path.startswith(f'/home/{server_name}/'):
        logger.warning(f"Security: Attempted folder deletion outside server directory by user {session.get('username')}")
        return jsonify({"success": False, "message": "Security violation: Access denied"}), 403
    
    try:
        # Check if folder exists
        if not os.path.exists(path) or not os.path.isdir(path):
            return jsonify({"success": False, "message": "Folder not found"}), 404
        
        # Check if this is a critical system folder
        critical_paths = [
            f'/home/{server_name}',
            f'/home/{server_name}/Zomboid',
            f'/home/{server_name}/PZServers'
        ]
        
        if path in critical_paths:
            return jsonify({"success": False, "message": "Cannot delete critical system folder"}), 403
        
        # Delete folder recursively
        shutil.rmtree(path)
        
        logger.info(f"User {session.get('username')} deleted folder {path}")
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Error deleting folder {path}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

# Configuration Management
def edit_server_config(server_name, config_type, config_data):
    config_paths = {
        "main": f"/home/{server_name}/Zomboid/Server/{server_name}.ini",
        "sandbox": f"/home/{server_name}/Zomboid/Server/{server_name}_SandboxVars.lua",
        "spawnregions": f"/home/{server_name}/Zomboid/Server/{server_name}_spawnregions.lua"
    }
    
    if config_type not in config_paths:
        logger.warning(f"Invalid configuration type requested: {config_type}")
        return False, "Invalid configuration type!"
    
    config_path = config_paths[config_type]
    
    try:
        # Ensure no extra spaces in configuration lines
        cleaned_config_lines = []
        for line in config_data.split('\n'):
            # Remove spaces around equal sign and strip whitespace
            line = re.sub(r'\s*=\s*', '=', line.strip())
            cleaned_config_lines.append(line)
        
        cleaned_config_data = '\n'.join(cleaned_config_lines)
        
        # Create directory structure if it doesn't exist
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            f.write(cleaned_config_data)
        
        # Set proper ownership
        subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', config_path], check=True)
        
        logger.info(f"Updated {config_type} configuration for server {server_name}")
        return True, "Configuration updated successfully!"
    except Exception as e:
        logger.error(f"Error updating {config_type} configuration for server {server_name}: {str(e)}")
        return False, f"Error updating configuration: {str(e)}"

def get_server_config(server_name, config_type):
    config_paths = {
        "main": f"/home/{server_name}/Zomboid/Server/{server_name}.ini",
        "sandbox": f"/home/{server_name}/Zomboid/Server/{server_name}_SandboxVars.lua",
        "spawnregions": f"/home/{server_name}/Zomboid/Server/{server_name}_spawnregions.lua"
    }
    
    if config_type not in config_paths:
        logger.warning(f"Invalid configuration type requested: {config_type}")
        return "Invalid configuration type!"
    
    config_path = config_paths[config_type]

    try:
        with open(config_path, 'r') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading {config_type} configuration for server {server_name}: {str(e)}")
        return f"Error reading configuration: {str(e)}"

def update_aws_backup_schedule(server_name, backup_config):
    """Update the backup schedule for a server using cron"""
    try:
        # Load existing AWS setup
        aws_setup = load_aws_cli_setup(server_name)
        
        # Update backup configuration
        aws_setup.update(backup_config)
        
        # Save configuration
        config_file = f'aws_cli_setup_{server_name}.json'
        with open(config_file, 'w') as f:
            json.dump(aws_setup, f, indent=4)

        # Log the AWS setup configuration
        logger.info(f"AWS setup configuration for {server_name}: {json.dumps(aws_setup.get('backup_enabled'), indent=4)}")
        
        # Generate backup script from template
        script_content = generate_backup_script(server_name, aws_setup)
        script_path = f'/home/{server_name}/backup_script.sh'
        
        # Create the script file
        try:
            # Use subprocess to create the file with the correct permissions
            with open('/tmp/temp_backup_script.sh', 'w') as f:
                f.write(script_content)
                
            # Copy the file to the correct location and set permissions
            subprocess.run(['sudo', 'mv', '/tmp/temp_backup_script.sh', script_path], check=True)
            subprocess.run(['sudo', 'chmod', '755', script_path], check=True)
            subprocess.run(['sudo', 'chown', f'{server_name}:{server_name}', script_path], check=True)
            
            logger.info(f"Created backup script at {script_path}")
        except Exception as e:
            logger.error(f"Error creating backup script file: {str(e)}")
            raise
        
        # Update cron job if automatic backups are enabled
        if aws_setup.get('backup_enabled') == True:
            success = setup_backup_cron(server_name, script_path, aws_setup)
            if not success:
                logger.warning(f"Failed to set up backup cron job for {server_name}")
            else:
                aws_setup['backup_enabled'] = True
                with open(config_file, 'w') as f:
                    json.dump(aws_setup, f, indent=4)
        else:
            # Remove any existing cron job if backups are disabled
            remove_backup_cron(server_name)
        logger.info(f"Updated backup configuration for server {server_name}")
        return True, "Backup configuration updated successfully"
    except Exception as e:
        logger.error(f"Error updating backup configuration for server {server_name}: {str(e)}")
        return False, f"Error updating backup configuration: {str(e)}"

# Logging Functions
def get_server_logs(server_name, lines=1000):
    """
    Retrieves server logs from either the main or webbase log file.
    
    Args:
        server_name (str): Name of the server
        lines (int): Number of lines to retrieve from the log
        
    Returns:
        str: HTML-formatted log content or error message
    """
    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='/tmp/server_log_retrieval.log',
        filemode='a'
    )
    
    # Define paths with absolute paths to avoid any path-related issues
    log_path = f'/home/{server_name}/Zomboid/server-console.txt'
    webbase_log_path = f'/home/{server_name}/Zomboid/server-console-webbase.txt'
    
    logging.debug(f"Attempting to get logs for {server_name}")
    logging.debug(f"Main log path: {log_path}, exists: {os.path.exists(log_path)}")
    logging.debug(f"Webbase log path: {webbase_log_path}, exists: {os.path.exists(webbase_log_path)}")
    
    try:
        # First try the main log file
        if os.path.exists(log_path) and os.access(log_path, os.R_OK):
            logging.debug("Main log file exists and is readable")
            
            try:
                # Use a timeout to prevent hanging on large files
                result = subprocess.run(
                    ['tail', '-n', str(lines), log_path], 
                    capture_output=True, 
                    text=True,
                    timeout=5
                )
                
                # Check if the output is empty
                if not result.stdout.strip():
                    logging.warning("Main log file exists but is empty or unreadable")
                    raise FileNotFoundError("Main log file is empty")
                
                # Try to update the webbase file
                try:
                    # Create parent directory if it doesn't exist
                    webbase_dir = os.path.dirname(webbase_log_path)
                    if not os.path.exists(webbase_dir):
                        os.makedirs(webbase_dir, exist_ok=True)
                    
                    # Write to the webbase file
                    with open(webbase_log_path, 'w') as webbase_file:
                        webbase_file.write(result.stdout)
                    
                    # Set proper ownership and permissions without using sudo
                    # This avoids potential sudo permission issues
                    os.chmod(webbase_log_path, 0o644)
                    
                except Exception as e:
                    logging.error(f"Failed to update webbase log: {str(e)}")
                    # Continue anyway as we still have the main log content
                
                # Return formatted logs
                formatted_logs = result.stdout.replace('\n', '<br>')
                logging.debug(f"Successfully returned {len(result.stdout.splitlines())} lines from main log")
                return formatted_logs
                
            except subprocess.TimeoutExpired:
                logging.error("Timeout while reading main log file")
                # Fall through to try webbase file
            except Exception as e:
                logging.error(f"Error reading main log file: {str(e)}")
                # Fall through to try webbase file
        
        # Try the webbase log if it exists
        if os.path.exists(webbase_log_path) and os.access(webbase_log_path, os.R_OK):
            logging.debug("Using webbase log file")
            
            try:
                # Read with timeout to prevent hanging
                with open(webbase_log_path, 'r') as webbase_file:
                    content = webbase_file.read()
                
                # Verify we got actual content
                if content.strip():
                    logging.debug(f"Successfully read {len(content.splitlines())} lines from webbase log")
                    return content.replace('\n', '<br>')
                else:
                    logging.warning("Webbase log file is empty")
            except Exception as e:
                logging.error(f"Error reading webbase log: {str(e)}")
        
        # If we got here, we couldn't read either file successfully
        logging.error("Neither main nor webbase log files could be read")
        
        # One last attempt - try direct read of DebugLog file that we can see exists in the tree output
        debug_log_path = f'/home/{server_name}/Zomboid/Logs/10-03-25_02-43-49_DebugLog-server.txt'
        if os.path.exists(debug_log_path) and os.access(debug_log_path, os.R_OK):
            try:
                result = subprocess.run(
                    ['tail', '-n', str(lines), debug_log_path], 
                    capture_output=True, 
                    text=True,
                    timeout=5
                )
                if result.stdout.strip():
                    logging.info("Successfully retrieved logs from DebugLog file")
                    return result.stdout.replace('\n', '<br>')
            except Exception as e:
                logging.error(f"Error reading DebugLog file: {str(e)}")
                
        # Last resort - try to create a new webbase log directly from main log if it exists
        if os.path.exists(log_path):
            try:
                # Simple file copy as last resort
                with open(log_path, 'r') as src, open(webbase_log_path, 'w') as dst:
                    last_lines = src.readlines()[-lines:] if lines > 0 else src.readlines()
                    dst.writelines(last_lines)
                
                # Read the newly created file
                with open(webbase_log_path, 'r') as webbase_file:
                    content = webbase_file.read()
                    if content.strip():
                        logging.info("Successfully recovered logs by direct file copy")
                        return content.replace('\n', '<br>')
            except Exception as e:
                logging.error(f"Final recovery attempt failed: {str(e)}")
        
        return f"Log files not available. Last check: {time.strftime('%Y-%m-%d %H:%M:%S')}"
    
    except Exception as e:
        error_msg = f"Critical error retrieving logs: {str(e)}"
        logging.critical(error_msg)
        return error_msg

@app.route('/server/<server_name>/logs/stream')
@login_required
def stream_server_logs(server_name):
    """Stream server logs in real-time using SSE"""
    
    def generate():
        last_size = [0]  # Using list for mutable closure variable
        last_check = [time.time()]
        log_buffer = []
        
        while True:
            try:
                # Define log paths
                log_path = f'/home/{server_name}/Zomboid/server-console.txt'
                
                # Heartbeat every 15 seconds even if no logs change
                current_time = time.time()
                if current_time - last_check[0] > 15:
                    yield f"data: {{\"heartbeat\": true}}\n\n"
                    last_check[0] = current_time
                    
                # Check if log file exists
                if os.path.exists(log_path):
                    current_size = os.path.getsize(log_path)
                    
                    # If file size changed or it's been 5+ seconds since last content update
                    if current_size != last_size[0] or current_time - last_check[0] > 5:
                        # Get the new content
                        with open(log_path, 'r', errors='replace') as f:
                            # If file grew too much, just get the end
                            if current_size - last_size[0] > 100000 and last_size[0] > 0:
                                f.seek(-100000, 2)  # Seek to 100KB from the end
                                f.readline()  # Skip potential partial line
                                logs = f.read()
                            elif last_size[0] > 0:
                                f.seek(last_size[0])
                                logs = f.read()
                            else:
                                # First read - get last 500 lines
                                logs = "".join(f.readlines()[-500:])
                        
                        if logs:
                            # Format logs for SSE - Escape quotes and newlines for JSON
                            logs_escaped = logs.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                            yield f"data: {{\"logs\": \"{logs_escaped}\"}}\n\n"
                            
                        last_size[0] = current_size
                        last_check[0] = current_time
                else:
                    # If log file doesn't exist
                    if time.time() - last_check[0] > 5:
                        yield f"data: {{\"logs\": \"Waiting for log file to be created...\", \"heartbeat\": true}}\n\n"
                        last_check[0] = time.time()
                
                # Slight pause to reduce CPU usage
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error in log streaming for {server_name}: {str(e)}")
                yield f"data: {{\"error\": \"{str(e)}\"}}\n\n"
                time.sleep(5)  # Longer pause after error
    
    return Response(generate(), mimetype="text/event-stream", headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
        'Connection': 'keep-alive'
    })

def log_server_action(server_name, action, username):
    """
    Logs server administrative actions to the server's log file
    
    Args:
        server_name: Name of the server
        action: The action being performed (restart, stop, etc)
        username: The administrator performing the action
    """
    
    logs_path = f'/home/{server_name}/Zomboid/server-console-webbase.txt'
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(logs_path), exist_ok=True)
        
        # Get current timestamp
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Create log message
        log_message = f"[{timestamp}] [ADMIN ACTION] User '{username}' {action} server.\n"
        
        # Append to log file
        with open(logs_path, 'a') as f:
            f.write(log_message)
        
        # Also log to pz_manager.log
        logger.info(f"Admin action: User '{username}' {action} server {server_name}")
            
        return True
    except Exception as e:
        logger.error(f"Error logging server action for {server_name}: {str(e)}")
        print(f"Error logging server action: {str(e)}")
        return False

@app.route('/server/create-with-output', methods=['POST'])
@login_required
@admin_required
def create_server_with_output():
    server_name = request.form.get('server_name', '').strip()
    admin_password = request.form.get('admin_password', '').strip()
    server_password = request.form.get('server_password', '').strip()
    port = int(request.form.get('port', 16261))
    query_port = int(request.form.get('query_port', 16262))
    rcon_port = int(request.form.get('rcon_port', 27015))
    
    # Generate a unique ID for this creation process
    creation_id = str(uuid.uuid4())
    
    # Initialize status tracking
    server_creation_status[creation_id] = {
        'server_name': server_name,
        'started_at': time.time(),
        'complete': False,
        'error': False,
        'error_message': None
    }
    
    # Create a queue for this specific server creation
    creation_queues[creation_id] = queue.Queue()
    
    # Store the creation session
    store_creation_session(creation_id, server_name, session.get('username'))
    
    # Start the creation process in a background thread
    creation_thread = threading.Thread(
        target=async_create_server,
        args=(server_name, admin_password, server_password, port, query_port, rcon_port, creation_id)
    )
    creation_thread.daemon = True
    creation_thread.start()
    
    logger.info(f"Server creation started by user {session.get('username')}: name={server_name}, creation_id={creation_id}")
    
    # Redirect to the creation page instead of returning JSON
    if request.form.get('redirect', 'true').lower() == 'true':
        return redirect(url_for('view_creation_by_id', creation_id=creation_id))
    else:
        # Return a response for API clients
        return jsonify({
            "status": "started",
            "creation_id": creation_id,
            "url": url_for('view_creation_by_id', creation_id=creation_id, _external=True),
            "message": "Server creation started. Check progress in the terminal output."
        })

# Player Management
def get_players_info(server_name):
    """
    Parse server logs to extract information about players who are:
    1. In queue (trying to connect)
    2. Currently in game
    
    Handles various log formats with timestamps to track player connection states.
    Returns a dictionary with player information.
    """
    from datetime import datetime
    
    # Define log paths
    logs_path = f'/home/{server_name}/Zomboid/server-console.txt'
    
    # Initialize player tracking
    players = {
        "in_queue": [],
        "in_game": []
    }
    
    # Player tracking with timestamps - defaultdict to automatically create entries
    player_status = defaultdict(lambda: {
        "status": "unknown", 
        "timestamp": 0, 
        "steam_id": "", 
        "ip": "",
        "access": "",
        "guid": ""
    })
    
    if not os.path.exists(logs_path):
        logger.warning(f"Server log file not found for player info: {logs_path}")
        return players
    
    try:
        with open(logs_path, 'r', errors='replace') as f:
            log_content = f.readlines()  # Read line by line for timestamp processing
            
        # Process log lines
        for line in log_content:
            # Extract timestamp from log line if available
            timestamp_match = re.search(r'\[(\d{2}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\]', line)
            timestamp = 0
            if timestamp_match:
                try:
                    # Convert timestamp to numeric format for comparison
                    time_str = timestamp_match.group(1)
                    dt = datetime.strptime(time_str, '%m-%d-%y %H:%M:%S.%f')
                    timestamp = dt.timestamp()
                except Exception:
                    pass
            
            # New pattern: Handle timestamp format from general logs
            alt_timestamp_match = re.search(r'(\d{10})\d+> \d+,\d+,\d+>', line)
            if alt_timestamp_match and timestamp == 0:
                try:
                    # Convert unix timestamp to datetime
                    unix_ts = int(alt_timestamp_match.group(1))
                    timestamp = unix_ts
                except Exception:
                    pass
            
            # Pattern for players trying to connect (original)
            if "User" in line and "is trying to connect" in line:
                connecting_match = re.search(r'User (\w+) is trying to connect', line)
                if connecting_match:
                    username = connecting_match.group(1)
                    player_status[username]["status"] = "connecting"
                    player_status[username]["timestamp"] = timestamp
            
            # New pattern: Alternative format for connection attempts
            alt_connecting_match = re.search(r'> User (\w+) is trying to connect', line)
            if alt_connecting_match:
                username = alt_connecting_match.group(1)
                player_status[username]["status"] = "connecting"
                player_status[username]["timestamp"] = timestamp
            
            # Process ping data if available (original)
            ping_match = re.search(r'GameServer\.receiveLogin > User (\w+) ping (\d+) ms', line)
            if ping_match:
                username = ping_match.group(1)
                ping = ping_match.group(2)
                player_status[username]["ping"] = ping
            
            # New pattern: Alternative format for ping data
            alt_ping_match = re.search(r'> GameServer\.receiveLogin > User (\w+) ping (\d+) ms', line)
            if alt_ping_match:
                username = alt_ping_match.group(1)
                ping = alt_ping_match.group(2)
                player_status[username]["ping"] = ping
            
            # Pattern for fully connected players (original)
            fully_connected_match = re.search(r'\[fully-connected\].+?connection: guid=(\d+) ip=([0-9\.]+) steam-id=(\d+) access=(\w+) username="([^"]+)"', line)
            if fully_connected_match:
                guid = fully_connected_match.group(1)
                ip = fully_connected_match.group(2)
                steam_id = fully_connected_match.group(3)
                access = fully_connected_match.group(4)
                username = fully_connected_match.group(5)
                
                # Update player status
                player_status[username]["status"] = "connected"
                player_status[username]["timestamp"] = timestamp
                player_status[username]["steam_id"] = steam_id
                player_status[username]["ip"] = ip
                player_status[username]["access"] = access
                player_status[username]["guid"] = guid
            
            # New pattern: Alternative format for fully connected players
            alt_connected_match = re.search(r'> \[fully-connected\] "".+?guid=(\d+) ip=([0-9\.]+) steam-id=(\d+) access=(\w*) username="([^"]+)"', line)
            if alt_connected_match:
                guid = alt_connected_match.group(1)
                ip = alt_connected_match.group(2)
                steam_id = alt_connected_match.group(3)
                access = alt_connected_match.group(4)
                username = alt_connected_match.group(5)
                
                # Update player status
                player_status[username]["status"] = "connected"
                player_status[username]["timestamp"] = timestamp
                player_status[username]["steam_id"] = steam_id
                player_status[username]["ip"] = ip
                player_status[username]["access"] = access
                player_status[username]["guid"] = guid

                # New pattern: Alternative format for fully connected players
            new_connected_match = re.search(r'\[fully-connected\] "" connection: guid=(\d+) ip=([0-9\.]+) steam-id=(\d+) access=(\w*) username="([^"]+)"', line)
            if new_connected_match:
                guid = new_connected_match.group(1)
                ip = new_connected_match.group(2)
                steam_id = new_connected_match.group(3)
                access = new_connected_match.group(4)
                username = new_connected_match.group(5)
                
                # Update player status
                player_status[username]["status"] = "connected"
                player_status[username]["timestamp"] = timestamp
                player_status[username]["steam_id"] = steam_id
                player_status[username]["ip"] = ip
                player_status[username]["access"] = access
                player_status[username]["guid"] = guid

            client_connect_new_pattern = re.search(r'\[receive-packet\] "client-connect" connection: guid=(\d+) ip=([0-9\.]+) steam-id=(\d+) access=(\w*) username="([^"]+)" connection-type="([^"]+)"', line)
            if client_connect_new_pattern:
                guid = client_connect_new_pattern.group(1)
                ip = client_connect_new_pattern.group(2)
                steam_id = client_connect_new_pattern.group(3)
                access = client_connect_new_pattern.group(4)
                username = client_connect_new_pattern.group(5)
                
                # Update connection data
                player_status[username]["steam_id"] = steam_id
                player_status[username]["ip"] = ip
                player_status[username]["access"] = access
                player_status[username]["guid"] = guid

            # Pattern for client connect (tracking initial connection)
            client_connect_match = re.search(r'\[receive-packet\] "client-connect".+?guid=(\d+) ip=([0-9\.]+) steam-id=(\d+) access=(\w+) username="([^"]+)"', line)
            if client_connect_match:
                guid = client_connect_match.group(1)
                ip = client_connect_match.group(2)
                steam_id = client_connect_match.group(3)
                access = client_connect_match.group(4)
                username = client_connect_match.group(5)
                
                # Update connection data
                player_status[username]["steam_id"] = steam_id
                player_status[username]["ip"] = ip
                player_status[username]["access"] = access
                player_status[username]["guid"] = guid
            
            # Patterns for disconnected players
            # Format 1: Simple disconnect message
            disconnect_simple_match = re.search(r'Disconnected player "([^"]+)" (\d+)', line)
            if disconnect_simple_match:
                username = disconnect_simple_match.group(1)
                steam_id = disconnect_simple_match.group(2)
                player_status[username]["status"] = "disconnected"
                player_status[username]["timestamp"] = timestamp
                player_status[username]["steam_id"] = steam_id
            
            # Format 2: Detailed disconnect message
            disconnect_detailed_match = re.search(r'\[disconnect\].+?guid=(\d+) ip=([0-9\.]+) steam-id=(\d+) access=(\w+) username="([^"]+)" connection-type="Disconnected"', line)
            if disconnect_detailed_match:
                guid = disconnect_detailed_match.group(1)
                ip = disconnect_detailed_match.group(2)
                steam_id = disconnect_detailed_match.group(3)
                access = disconnect_detailed_match.group(4)
                username = disconnect_detailed_match.group(5)
                
                player_status[username]["status"] = "disconnected"
                player_status[username]["timestamp"] = timestamp
                player_status[username]["steam_id"] = steam_id
                player_status[username]["ip"] = ip
                player_status[username]["access"] = access
                player_status[username]["guid"] = guid
            
            # Format 3: Connection lost message
            connection_lost_match = re.search(r'\[RakNet\] "connection-lost".+?guid=(\d+) ip=([0-9\.]+) steam-id=(\d+) access=(\w+) username="([^"]+)"', line)
            if connection_lost_match:
                guid = connection_lost_match.group(1)
                ip = connection_lost_match.group(2)
                steam_id = connection_lost_match.group(3)
                access = connection_lost_match.group(4)
                username = connection_lost_match.group(5)
                
                player_status[username]["status"] = "disconnected"
                player_status[username]["timestamp"] = timestamp
                player_status[username]["steam_id"] = steam_id
                player_status[username]["ip"] = ip
                player_status[username]["access"] = access
                player_status[username]["guid"] = guid
        
        # Build final player lists based on the most recent status
        for username, data in player_status.items():
            player_info = {
                "username": username,
                "steam_id": data.get("steam_id", ""),
                "ip": data.get("ip", ""),
                "access": data.get("access", ""),
                "guid": data.get("guid", ""),
                "timestamp": data.get("timestamp", 0)
            }
            
            # Add ping if available
            if "ping" in data:
                player_info["ping"] = data["ping"]
                
            if data["status"] == "connecting":
                players["in_queue"].append(player_info)
            elif data["status"] == "connected":
                # Check if player has connected and not disconnected
                # A player is considered in game if their last status is "connected"
                players["in_game"].append(player_info)
        
        # Sort players by timestamp (most recent first)
        players["in_queue"].sort(key=lambda x: x["timestamp"], reverse=True)
        players["in_game"].sort(key=lambda x: x["timestamp"], reverse=True)
        
        logger.debug(f"Found {len(players['in_game'])} players in game and {len(players['in_queue'])} in queue for server {server_name}")
        return players
    except Exception as e:
        logger.error(f"Error parsing player information for server {server_name}: {str(e)}")
        print(f"Error parsing player information: {str(e)}")
        return players

def add_banned_player(server_name, username, steam_id=None, ip=None, reason=None, duration="permanent", admin_name=None):
    """Add a player to the banned list for a specific server"""
    try:
        data = load_banned_players()
        
        # Ensure server entry exists
        if server_name not in data["servers"]:
            data["servers"][server_name] = {}
        
        # Create ban entry
        ban_timestamp = int(time.time())
        expiry = None
        
        # If duration is a number, calculate expiry
        if isinstance(duration, (int, float)) or (isinstance(duration, str) and duration.isdigit()):
            days = int(float(duration))
            expiry = ban_timestamp + (days * 86400)  # Convert days to seconds
        
        data["servers"][server_name][username] = {
            "username": username,
            "steam_id": steam_id,
            "ip": ip,
            "reason": reason,
            "banned_at": ban_timestamp,
            "banned_by": admin_name,
            "duration": duration,
            "expiry": expiry
        }
        
        save_banned_players(data)
        logger.info(f"Player {username} added to ban list for server {server_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to add banned player {username} to {server_name}: {str(e)}")
        return False

def remove_banned_player(server_name, username):
    """Remove a player from the banned list for a specific server"""
    try:
        data = load_banned_players()
        
        if server_name in data["servers"] and username in data["servers"][server_name]:
            del data["servers"][server_name][username]
            save_banned_players(data)
            logger.info(f"Player {username} removed from ban list for server {server_name}")
            return True
        
        logger.warning(f"Attempt to unban non-existent player {username} from server {server_name}")
        return False
    except Exception as e:
        logger.error(f"Failed to remove banned player {username} from {server_name}: {str(e)}")
        return False

def get_banned_players(server_name):
    """Get the list of banned players for a specific server"""
    try:
        data = load_banned_players()
        
        if server_name in data["servers"]:
            # Filter out expired bans
            current_time = int(time.time())
            active_bans = {}
            
            for username, ban_info in data["servers"][server_name].items():
                # Keep permanent bans and non-expired temporary bans
                if ban_info.get("expiry") is None or ban_info.get("expiry", 0) > current_time:
                    active_bans[username] = ban_info
                else:
                    logger.debug(f"Expired ban removed for player {username} on server {server_name}")
            
            # Update the data if we removed any expired bans
            if len(active_bans) != len(data["servers"][server_name]):
                data["servers"][server_name] = active_bans
                save_banned_players(data)
            
            return list(active_bans.values())
        
        return []
    except Exception as e:
        logger.error(f"Error retrieving banned players for {server_name}: {str(e)}")
        return []

@app.route('/users/delete/<username>')
@login_required
@admin_required
def delete_user(username):
    if username == 'admin':
        flash('Cannot delete admin user', 'danger')
        logger.warning(f"User {session.get('username')} attempted to delete the admin user")
        return redirect(url_for('users'))
    
    if username == session['username']:
        flash('Cannot delete yourself', 'danger')
        logger.warning(f"User {session.get('username')} attempted to delete themselves")
        return redirect(url_for('users'))
    
    with open(USERS_FILE, 'r') as f:
        data = json.load(f)
    
    if username in data["users"]:
        del data["users"][username]
        
        with open(USERS_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        
        flash('User deleted successfully', 'success')
        logger.info(f"User {session.get('username')} deleted user: {username}")
    else:
        flash('User not found', 'danger')
        logger.warning(f"User {session.get('username')} attempted to delete non-existent user: {username}")
    
    return redirect(url_for('users'))

# System Monitoring
def collect_system_and_server_stats():
    """Collect system and per-server statistics"""
    try:
        # CPU stats
        cpu_usage = psutil.cpu_percent(interval=0)
        
        # Memory stats
        memory = psutil.virtual_memory()
        memory_total = round(memory.total / (1024**3), 2)
        memory_used = round(memory.used / (1024**3), 2)
        memory_percentage = memory.percent
        
        # Disk stats
        disk = psutil.disk_usage('/')
        disk_total = round(disk.total / (1024**3), 2)
        disk_used = round(disk.used / (1024**3), 2)
        disk_percentage = disk.percent
        
        # Network stats calculation
        net_io_file = '/tmp/pz_net_io_stats.json'
        net_io_counters = psutil.net_io_counters()
        
        network_traffic = 0
        try:
            if os.path.exists(net_io_file):
                with open(net_io_file, 'r') as f:
                    old_stats = json.load(f)
                    last_time = old_stats['time']
                    time_diff = time.time() - last_time
                    
                    if time_diff > 0:
                        bytes_sent_diff = net_io_counters.bytes_sent - old_stats['bytes_sent']
                        bytes_recv_diff = net_io_counters.bytes_recv - old_stats['bytes_recv']
                        network_traffic = round((bytes_sent_diff + bytes_recv_diff) / (1024**2) / time_diff, 2)
        except Exception as e:
            logger.debug(f"Error calculating network traffic: {str(e)}")
            network_traffic = 0
            
        # Store current counters for next calculation
        with open(net_io_file, 'w') as f:
            json.dump({
                'bytes_sent': net_io_counters.bytes_sent,
                'bytes_recv': net_io_counters.bytes_recv,
                'time': time.time()
            }, f)
        
        # System uptime calculation
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.datetime.now() - boot_time
        uptime_str = f"{uptime.days}d {uptime.seconds // 3600}h {(uptime.seconds // 60) % 60}m"
        
        # Load average
        load_avg = psutil.getloadavg()[0]
        
        # Per-server statistics
        data = load_servers()
        active_servers = sum(1 for server in data["servers"].values() if server["status"] == "running")
        server_stats = {}
        
        for server_name, server_info in data["servers"].items():
            # Only collect detailed stats for running servers
            if server_info["status"] == "running":
                server_stats[server_name] = get_server_resource_stats(server_name)
        
        # CPU temperature
        temperature = get_cpu_temperature()
        
        # Build complete stats object
        return {
            'cpu': {'usage': cpu_usage},
            'memory': {
                'total': memory_total,
                'used': memory_used,
                'percentage': memory_percentage
            },
            'disk': {
                'total': disk_total,
                'used': disk_used,
                'percentage': disk_percentage
            },
            'network': {
                'traffic': network_traffic,
                'percentage': min(network_traffic * 10, 100)
            },
            'uptime': uptime_str,
            'active_servers': active_servers,
            'load_average': round(load_avg, 2),
            'temperature': temperature,
            'servers': server_stats,
            'timestamp': int(time.time())
        }
    except Exception as e:
        logger.error(f"Error collecting system stats: {str(e)}")
        return {"error": str(e)}

def get_server_resource_stats(server_name):
    """Get resource stats for a specific server"""
    try:
        # Find processes for this server
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            if (proc.info['username'] == server_name or 
                (proc.info['cmdline'] and server_name in ' '.join(proc.info['cmdline']))):
                processes.append(proc)
        
        if not processes:
            return {}
        
        # Calculate resource usage
        cpu_percent_sum = 0
        memory_usage_sum = 0
        for proc in processes:
            try:
                cpu_percent_sum += proc.cpu_percent(interval=0.1)
                memory_info = proc.memory_info()
                memory_usage_sum += memory_info.rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Get server start time for uptime
        start_time = max((proc.create_time() for proc in processes if proc.is_running()), default=0)
        
        # Calculate uptime
        uptime_seconds = int(time.time() - start_time) if start_time else 0
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_str = f"{hours:02}:{minutes:02}:{seconds:02}"
        
        # Get server directory size
        server_dir = f"/home/{server_name}"
        disk_usage = 0
        if os.path.exists(server_dir):
            try:
                result = subprocess.run(['du', '-s', server_dir], 
                                      capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    disk_usage = int(result.stdout.split()[0])
            except Exception:
                # Fallback method if du fails
                pass
        
        # Convert memory to MB and round
        memory_usage_mb = round(memory_usage_sum / (1024 * 1024), 1)
        
        # Estimate network usage
        data = load_servers()
        running_servers = sum(1 for s in data["servers"].values() if s["status"] == "running")
        net_io_counters = psutil.net_io_counters()
        network_traffic = 0
        
        # Read network stats from temp file
        net_io_file = '/tmp/pz_net_io_stats.json'
        if os.path.exists(net_io_file):
            try:
                with open(net_io_file, 'r') as f:
                    net_stats = json.load(f)
                    network_traffic = (net_stats.get('traffic', 0) * 1024) / max(running_servers, 1)
            except Exception:
                network_traffic = 0
                
        return {
            'cpu_usage': round(cpu_percent_sum, 1),
            'memory_usage': memory_usage_mb,
            'memory_percentage': min(round(memory_usage_mb / (psutil.virtual_memory().total / (1024 * 1024)) * 100, 1), 100),
            'disk_usage': round(disk_usage / 1024, 1),
            'disk_percentage': min(round(disk_usage / (1024 * 1024) * 100, 1), 100),
            'network_traffic': round(network_traffic, 1),
            'network_percentage': min(round(network_traffic / 10, 1), 100),
            'uptime': uptime_str
        }
        
    except Exception as e:
        logger.error(f"Error getting server stats for {server_name}: {str(e)}")
        return {}

# Utility Functions
def is_port_in_use(port):
    """Check if a port is in use by any process on the system"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0
  
def find_available_port(start_port):
    """Find the next available port starting from start_port"""
    port = start_port
    while is_port_in_use(port):
        port += 1
    return port

def generate_backup_script(server_name, aws_setup):
   """Generate backup script content based on server folder structure"""
   script = f"""#!/bin/bash

# Configuration variables
SERVER_NAME="{server_name}"
ZOMBOID_PATH="/home/${{SERVER_NAME}}/Zomboid"
BACKUP_PATH="/home/${{SERVER_NAME}}/backups/${{SERVER_NAME}}"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="${{SERVER_NAME}}_backup_${{DATE}}.tar.gz"

# S3 Configuration
S3_BUCKET="{aws_setup.get('bucket_name', '')}"
S3_ENDPOINT="{aws_setup.get('endpoint_url', '')}"
S3_PROFILE="{aws_setup.get('profile_name', 'r2')}"
RETENTION_COUNT={aws_setup.get('retention_count', 10)}

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_PATH"

# Log start of backup
echo "[$(date)] Starting backup of ${{SERVER_NAME}}" >> "$BACKUP_PATH/backup.log"

# Check if server is running
screen -list | grep -q "$SERVER_NAME"
if [ $? -eq 0 ]; then
  # Get the screen session ID
  SESSION_ID=$(screen -list | grep "$SERVER_NAME" | awk '{{print $1}}')
  
  if [ -n "$SESSION_ID" ]; then
    # Send save command to the server
    echo "[$(date)] Server is running, sending save command..." >> "$BACKUP_PATH/backup.log"
    screen -S "$SESSION_ID" -X stuff "save\\n"
    
    # Wait for save to complete
    echo "[$(date)] Waiting 10 seconds for save to complete..." >> "$BACKUP_PATH/backup.log"
    sleep 10
  else
    echo "[$(date)] Server appears running but couldn't get session ID" >> "$BACKUP_PATH/backup.log"
  fi
else
  echo "[$(date)] Server not running, proceeding with backup of current files" >> "$BACKUP_PATH/backup.log"
fi

# Get backup items from user selection
BACKUP_DIRS=(
 {' '.join([f'"{item}"' for item in aws_setup.get('backup_items', ['Saves/Multiplayer', 'Server', 'db'])])}
)

# Create the backup with proper paths
tar -czf "$BACKUP_PATH/$BACKUP_NAME" \\
  -C "$ZOMBOID_PATH" \\
  "${{BACKUP_DIRS[@]}}"

# Log backup creation
echo "[$(date)] Created backup: $BACKUP_NAME ($(du -h "$BACKUP_PATH/$BACKUP_NAME" | cut -f1))" >> "$BACKUP_PATH/backup.log"

# Keep only the specified number of backups locally
if [ $RETENTION_COUNT -gt 0 ]; then
  cd "$BACKUP_PATH" && ls -t ${{SERVER_NAME}}_backup_*.tar.gz | tail -n +$(($RETENTION_COUNT+1)) | xargs -r rm
  echo "[$(date)] Cleaned old local backups (keeping $RETENTION_COUNT)" >> "$BACKUP_PATH/backup.log"
fi

# Upload to S3 if configured
if [ -n "$S3_BUCKET" ] && [ -n "$S3_ENDPOINT" ] && [ -n "$S3_PROFILE" ]; then
  echo "[$(date)] Uploading to S3: $S3_BUCKET" >> "$BACKUP_PATH/backup.log"
  
  # Upload to S3 with server name as folder prefix
  aws s3 cp "$BACKUP_PATH/$BACKUP_NAME" "s3://$S3_BUCKET/$SERVER_NAME/" \\
      --endpoint-url "$S3_ENDPOINT" \\
      --profile "$S3_PROFILE"
  
  if [ $? -eq 0 ]; then
      echo "[$(date)] Successfully uploaded to S3" >> "$BACKUP_PATH/backup.log"
  else
      echo "[$(date)] Failed to upload to S3" >> "$BACKUP_PATH/backup.log"
  fi
  
  # List and clean S3 backups (keep only specified number)
  if [ $RETENTION_COUNT -gt 0 ]; then
      BACKUPS_TO_DELETE=$(aws s3 ls "s3://$S3_BUCKET/$SERVER_NAME/" \\
          --endpoint-url "$S3_ENDPOINT" \\
          --profile "$S3_PROFILE" \\
          | grep "${{SERVER_NAME}}_backup_" \\
          | sort -r \\
          | tail -n +$(($RETENTION_COUNT+1)) \\
          | awk '{{print $4}}')

      # Delete old S3 backups
      for backup in $BACKUPS_TO_DELETE; do
          aws s3 rm "s3://$S3_BUCKET/$SERVER_NAME/$backup" \\
              --endpoint-url "$S3_ENDPOINT" \\
              --profile "$S3_PROFILE"
      done
      echo "[$(date)] Cleaned old S3 backups (keeping $RETENTION_COUNT)" >> "$BACKUP_PATH/backup.log"
  fi
else
  echo "[$(date)] S3 upload skipped - not configured" >> "$BACKUP_PATH/backup.log"
fi

echo "[$(date)] Backup completed: $BACKUP_PATH/$BACKUP_NAME" >> "$BACKUP_PATH/backup.log"
"""
   
   return script

# Authentication Routes
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if authenticate_user(username, password):
            session['username'] = username
            session['is_admin'] = is_admin(username)
            logger.info(f"User {username} logged in successfully")
            
            # Set cache-busting flag in session
            session['clear_cache'] = True
            
            # Set no-cache headers
            response = redirect(url_for('dashboard'))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        else:
            flash('Invalid username or password')
            logger.warning(f"Failed login attempt for user: {username}")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.pop('username', None)
    session.pop('is_admin', None)
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    update_server_statuses()
    data = load_servers()
    logger.debug(f"Dashboard accessed by user: {session.get('username')}")
    
    # Prepare response
    response = make_response(render_template('dashboard.html', 
                            servers=data["servers"],
                            is_admin=session.get('is_admin', False),
                            clear_cache=session.pop('clear_cache', False)))
    
    # Add cache-busting headers
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/users')
@login_required
@admin_required
def users():
    with open(USERS_FILE, 'r') as f:
        data = json.load(f)
    
    logger.debug(f"User {session.get('username')} accessed user management page")
    return render_template('users.html', users=data["users"])

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user_route():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        
        with open(USERS_FILE, 'r') as f:
            data = json.load(f)
        
        if username in data["users"]:
            flash('Username already exists', 'danger')
            logger.warning(f"User {session.get('username')} attempted to create duplicate user: {username}")
        else:
            hash_password = hashlib.sha256(password.encode()).hexdigest()
            add_user(username, hash_password, is_admin)
            flash('User added successfully', 'success')
            logger.info(f"User {session.get('username')} created new user: {username} (admin: {is_admin})")
            return redirect(url_for('users'))
    
    return render_template('add_user.html')

# Server Management Routes
@app.route('/api/creation-sessions')
@login_required
def api_creation_sessions():
    """API endpoint to get all server creation sessions"""
    try:
        data = load_creation_sessions()
        
        # Convert creation sessions to a list and enhance with additional information
        sessions_list = []
        for creation_id, session_data in data["sessions"].items():
            session_info = session_data.copy()
            session_info['creation_id'] = creation_id
            sessions_list.append(session_info)
        
        # Sort by started_at timestamp (newest first)
        sessions_list.sort(key=lambda x: x.get('started_at', 0), reverse=True)
        
        return jsonify({"success": True, "sessions": sessions_list})
    except Exception as e:
        logger.error(f"Error retrieving creation sessions: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/servers-status')
@login_required
def api_servers_status():
    """Check if any servers need UI refresh"""
    data = load_servers()
    refresh_needed = any(server.get("marked") == "finish" for server in data["servers"].values())
    
    if refresh_needed:
        # Update servers marked as "finish" to normal
        for server_name, server_info in data["servers"].items():
            if server_info.get("marked") == "finish":
                data["servers"][server_name]["marked"] = ""
        save_servers(data)
    
    return jsonify({"refresh_needed": refresh_needed})

@app.route('/server/create', methods=['GET'])
@login_required
@admin_required
def create_server_route():
    logger.debug(f"User {session.get('username')} accessed server creation page")
    return render_template('create_server.html')

@app.route('/server/<server_name>/control')
@login_required
def server_control(server_name):
    data = load_servers()
    
    if server_name not in data["servers"]:
        flash('Server not found!')
        logger.warning(f"Control panel access attempt for non-existent server: {server_name}")
        return redirect(url_for('dashboard'))
    
    # Update status
    data["servers"][server_name]["status"] = get_server_status(server_name)
    save_servers(data)
    
    logs = get_server_logs(server_name)
    
    logger.debug(f"User {session.get('username')} accessed control panel for server {server_name}")
    return render_template('server_control.html',
                            server=data["servers"][server_name],
                            logs=logs,
                            is_admin=session.get('is_admin', False))

@app.route('/server/<server_name>/start', methods=['GET', 'POST'])
@login_required
@admin_required
def start_server_route(server_name):
    # Log the start action
    log_server_action(server_name, "started", session.get('username', 'unknown'))
    logger.info(f"User {session.get('username')} started server {server_name}")
    
    success, message = start_server(server_name)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    
    # For POST requests (AJAX calls), return JSON
    if request.method == 'POST':
        return jsonify({"success": success, "message": message})
    
    # For GET requests (direct access), redirect to control page
    return redirect(url_for('server_control', server_name=server_name))

@app.route('/server/<server_name>/stop', methods=['GET', 'POST'])
@login_required
@admin_required
def stop_server_route(server_name):
    # Log the stop action
    log_server_action(server_name, "stopped", session.get('username', 'unknown'))
    logger.info(f"User {session.get('username')} stopped server {server_name}")
    
    success, message = stop_server(server_name)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    
    # For POST requests (AJAX calls), return JSON
    if request.method == 'POST':
        return jsonify({"success": success, "message": message})
    
    # For GET requests (direct access), redirect to control page
    return redirect(url_for('server_control', server_name=server_name))

@app.route('/server/<server_name>/restart', methods=['GET', 'POST'])
@login_required
@admin_required
def restart_server_route(server_name):
    # Log the restart action
    log_server_action(server_name, "requested to restart", session.get('username', 'unknown'))
    logger.info(f"User {session.get('username')} initiated server restart for {server_name}")
    
    # Perform the restart
    success, message = restart_server(server_name)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    
    # For POST requests (AJAX calls), return JSON
    if request.method == 'POST':
        return jsonify({"success": success, "message": message})
    
    # For GET requests (direct access), redirect to control page
    return redirect(url_for('server_control', server_name=server_name))

@app.route('/server/<server_name>/delete', methods=['POST'])
@login_required
@admin_required
def delete_server_route(server_name):
    # Note: Changed from GET to POST method for better security
    log_server_action(server_name, "deleted", session.get('username', 'unknown'))
    logger.info(f"User {session.get('username')} deleted server {server_name}")
    
    success, message = delete_server(server_name)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    
    return jsonify({"success": success, "message": message})

@app.route('/server/<server_name>/logs')
@login_required
def server_logs(server_name):
    lines = request.args.get('lines', default=100, type=int)
    logs = get_server_logs(server_name, lines)
    logger.debug(f"User {session.get('username')} retrieved logs for server {server_name} ({lines} lines)")
    return jsonify({"logs": logs})

@app.route('/server/<server_name>/files')
@login_required
def server_file_manager(server_name):
    """Render the file manager page for a server"""
    data = load_servers()
    
    if server_name not in data["servers"]:
        flash('Server not found!')
        logger.warning(f"File manager access attempt for non-existent server: {server_name}")
        return redirect(url_for('dashboard'))
    
    # Update status
    data["servers"][server_name]["status"] = get_server_status(server_name)
    save_servers(data)
    
    logger.debug(f"User {session.get('username')} accessed file manager for server {server_name}")
    return render_template('server_file_manager.html',
                          server=data["servers"][server_name],
                          is_admin=session.get('is_admin', False))

@app.route('/server/create/<creation_id>')
@login_required
@admin_required
def view_creation_by_id(creation_id):
    # Get the creation session
    session_data = get_creation_session(creation_id)
    
    if not session_data:
        flash('Creation session not found or expired', 'danger')
        logger.warning(f"User {session.get('username')} attempted to view non-existent creation session: {creation_id}")
        return redirect(url_for('dashboard'))
    
    # Check if the user has permission to view this session
    if session.get('username') != session_data['username'] and not is_admin(session.get('username')):
        flash('You do not have permission to view this creation session', 'danger')
        logger.warning(f"User {session.get('username')} attempted to view creation session belonging to {session_data['username']}")
        return redirect(url_for('dashboard'))
    
    # Check if the creation is still in the status dictionary
    # If not, we'll still show the page but with a notice that live logs aren't available
    creation_active = creation_id in server_creation_status
    
    server_name = session_data.get('server_name', 'unknown')
    status = session_data.get('status', 'unknown')
    
    # Clean up idle queues if needed
    cleanup_idle_creation_queues()
    
    # Create a sessions list with just this creation session
    sessions = [{
        "server_name": server_name,
        "status": status,
        "started_at": datetime.datetime.fromtimestamp(session_data.get('started_at', 0)).strftime('%Y-%m-%d %H:%M:%S'),
        "creation_id": creation_id
    }]
    
    return render_template('view_server_creation.html',
                          creation_id=creation_id,
                          server_name=server_name,
                          creation_active=creation_active,
                          status=status,
                          sessions=sessions)  # Pass sessions to the template

@app.route('/api/creation-stream/<creation_id>')
@login_required
def creation_stream(creation_id):
   """Server-sent events stream for creation status updates"""
   def generate():
       # Check if creation_id exists
       if creation_id not in creation_queues:
           logger.warning(f"No active creation process found for ID: {creation_id}")
           yield f"data: {json.dumps({'message': 'No active creation process found.', 'complete': True})}\n\n"
           return
       
       queue_instance = creation_queues[creation_id]
       
       # Send initial message
       server_name = server_creation_status[creation_id].get('server_name', 'unknown')
       yield f"data: {json.dumps({'message': f'<br>Starting server creation process for {server_name}...'})}\n\n"
       
       # Flush stdout to ensure messages are sent immediately
       sys.stdout.flush()
       
       while True:
           try:
               # Try to get message with a shorter timeout to be more responsive
               try:
                   msg = queue_instance.get(timeout=0.5)
                   yield f"data: {json.dumps(msg)}\n\n"
                   
                   # Explicitly flush after each message
                   sys.stdout.flush()
                   
                   # If the process is complete, clean up
                   if msg.get('complete', False):
                       logger.debug(f"Stream for {creation_id} completed")
                       break
                       
               except queue.Empty:
                   # Check if the process is still active
                   if creation_id in server_creation_status:
                       if server_creation_status[creation_id].get('complete', False):
                           yield f"data: {json.dumps({'message': 'Server creation completed.', 'complete': True})}\n\n"
                           break
                   else:
                       yield f"data: {json.dumps({'message': 'Creation process not found or completed.', 'complete': True})}\n\n"
                       break
                   
                   # Send a heartbeat to keep the connection alive
                   yield f"data: {json.dumps({'message': '', 'heartbeat': True})}\n\n"
                   sys.stdout.flush()
                   
           except Exception as e:
               logger.error(f"Error in server creation status stream for ID {creation_id}: {str(e)}")
               yield f"data: {json.dumps({'message': f'Error: {str(e)}', 'error': True, 'complete': True})}\n\n"
               break
       
       # Final cleanup after a completed stream
       logger.debug(f"Stream for {creation_id} ending, cleaning up queue")
       if creation_id in creation_queues:
           while not creation_queues[creation_id].empty():
               creation_queues[creation_id].get_nowait()

   return Response(generate(), mimetype='text/event-stream', headers={
       'Cache-Control': 'no-cache',
       'X-Accel-Buffering': 'no',  # Disable NGINX buffering
       'Connection': 'keep-alive'
   })

# API Routes
@app.route('/api/servers-list')
@login_required
def api_servers_list():
    """Return list of valid servers from config"""
    data = load_servers()
    servers_list = [{"name": name, "status": info["status"]} 
                   for name, info in data["servers"].items()]
    return jsonify({"success": True, "servers": servers_list}) 

@app.route('/api/server/<server_name>/status')
@login_required
def api_server_status(server_name):
   status = get_server_status(server_name)
   logger.debug(f"Status check for server {server_name}: {status}")
   return jsonify({"status": status})

@app.route('/api/server/<server_name>/players')
@login_required
def get_server_players(server_name):
    """API endpoint to get current players for a server"""
    # Check if server exists
    data = load_servers()
    if server_name not in data["servers"]:
        logger.warning(f"Player list requested for non-existent server: {server_name}")
        return jsonify({"success": False, "message": "Server not found"}), 404
    
    try:
        # Get player information from logs
        players_info = get_players_info(server_name)
        
        logger.debug(f"Retrieved player list for server {server_name}: {len(players_info['in_game'])} in game, {len(players_info['in_queue'])} in queue")
        return jsonify({
            "success": True, 
            "players": players_info,
            "counts": {
                "in_queue": len(players_info["in_queue"]),
                "in_game": len(players_info["in_game"]),
                "total": len(players_info["in_queue"]) + len(players_info["in_game"])
            }
        })
    except Exception as e:
        logger.error(f"Error retrieving players for server {server_name}: {str(e)}")
        return jsonify({"success": False, "message": f"Error retrieving players: {str(e)}"}), 500

@app.route('/api/server/<server_name>/mods')
@login_required
def server_mods(server_name):
    """Get a list of installed mods for the server from Steam Workshop"""
    try:
        # Check if server exists
        data = load_servers()
        if server_name not in data["servers"]:
            logger.warning(f"Mod list requested for non-existent server: {server_name}")
            return jsonify({"success": False, "message": "Server not found"}), 404
        
        # Path to Steam Workshop content for Project Zomboid
        workshop_path = f"/home/{server_name}/PZServers/steamapps/workshop/content/108600"
        
        # Check if the workshop directory exists
        if not os.path.exists(workshop_path):
            logger.info(f"No workshop directory found for server {server_name}")
            return jsonify({"success": True, "mods": []})
        
        mods = []
        
        # Iterate through all mod directories (each is identified by its Steam Workshop ID)
        for mod_id in os.listdir(workshop_path):
            # Skip if not a directory or doesn't look like a numeric ID
            if not os.path.isdir(os.path.join(workshop_path, mod_id)) or not mod_id.isdigit():
                continue
            
            # Initialize mod info
            mod_info = {
                "id": mod_id,
                "name": None,
                "path": f"workshop/content/108600/{mod_id}"
            }
            
            # Try to find the mod name from the mod directory structure
            mod_base_dir = os.path.join(workshop_path, mod_id)
            
            # Look for mods directory which typically contains the actual mod folders
            mods_dir = os.path.join(mod_base_dir, "mods")
            if os.path.exists(mods_dir):
                # Get the first subdirectory in the mods folder - this is usually the mod name
                subdirs = [d for d in os.listdir(mods_dir) if os.path.isdir(os.path.join(mods_dir, d))]
                if subdirs:
                    mod_info["name"] = subdirs[0]
                    mod_info["path"] = f"workshop/content/108600/{mod_id}/mods/{subdirs[0]}"
                    # Found what we need, no need to search more
                    mods.append(mod_info)
                    continue
            
            # More efficient mod.info file search - limit depth and stop after finding
            found_mod_info = False
            for root, dirs, files in os.walk(mod_base_dir, topdown=True, followlinks=False):
                # Limit directory depth to prevent excessive searching
                depth = root[len(mod_base_dir):].count(os.path.sep)
                if depth > 2:  # Only search to a reasonable depth
                    dirs[:] = []  # Stop going deeper in this branch
                    continue
                
                if "mod.info" in files:
                    try:
                        with open(os.path.join(root, "mod.info"), 'r', errors='ignore') as f:
                            content = f.read(500)  # Read just first 500 chars, enough for name
                            match = re.search(r'name=(.+?)(\n|$)', content)
                            if match:
                                mod_info["name"] = match.group(1).strip()
                                found_mod_info = True
                                break
                    except Exception:
                        pass
                    
                if found_mod_info:
                    break
            
            # If we still don't have a name, use the directory name from the first subdirectory
            if not mod_info["name"]:
                # Don't recursively search - just look at immediate subdirectories
                subdirs = [d for d in os.listdir(mod_base_dir) if os.path.isdir(os.path.join(mod_base_dir, d))]
                if subdirs:
                    mod_info["name"] = subdirs[0]
            
            # If we still can't determine the name, use a placeholder
            if not mod_info["name"]:
                mod_info["name"] = f"Workshop Item {mod_id}"
            
            mods.append(mod_info)
        
        # Sort mods alphabetically by name
        mods.sort(key=lambda x: x["name"].lower() if x["name"] else "")
        
        logger.info(f"Retrieved {len(mods)} mods for server {server_name}")
        return jsonify({"success": True, "mods": mods})
    
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error retrieving mods for server {server_name}: {error_details}")
        print(f"Error retrieving mods: {error_details}")
        return jsonify({"success": False, "message": f"Error retrieving mods: {str(e)}"}), 500

@app.route('/api/server-stats-stream')
@login_required
def server_stats_stream():
    """Stream server statistics in real-time using Server-Sent Events (SSE)"""
    
    def generate():
        last_update = time.time()
        last_stats_hash = None
        
        while True:
            try:
                current_time = time.time()
                
                # Send heartbeat every 30 seconds
                if current_time - last_update > 30:
                    yield f"event: heartbeat\ndata: {current_time}\n\n"
                
                # Collect all stats
                stats = collect_system_and_server_stats()
                
                # Hash the stats to check if they changed
                stats_json = json.dumps(stats)
                current_hash = hashlib.md5(stats_json.encode()).hexdigest()
                
                # Send update if stats changed or interval passed
                if last_stats_hash != current_hash or current_time - last_update > 5:
                    yield f"event: stats_update\ndata: {stats_json}\n\n"
                    last_stats_hash = current_hash
                    last_update = current_time
                
                # Sleep for a reasonable interval
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error in stats stream: {str(e)}")
                yield f"event: error\ndata: {str(e)}\n\n"
                time.sleep(5)
    
    return Response(generate(), 
                   mimetype="text/event-stream",
                   headers={
                       'Cache-Control': 'no-cache',
                       'X-Accel-Buffering': 'no', 
                       'Connection': 'keep-alive'
                   })

@app.route('/api/server-creation-status/<creation_id>')
def server_creation_status_redirect(creation_id):
    """Handle direct access to the SSE endpoint by redirecting to the HTML view"""
    # Redirect to the view_creation_by_id route
    return redirect(url_for('view_creation_by_id', creation_id=creation_id))

# Additional Routes
@app.route('/server/<server_name>/settings')
@login_required
@admin_required
def server_settings(server_name):
    """Render the server settings page"""
    data = load_servers()
    
    if server_name not in data["servers"]:
        flash('Server not found!')
        return redirect(url_for('dashboard'))
    
    # Check if AWS CLI is installed
    aws_installed = is_aws_cli_installed()
    
    # Load AWS CLI setup info
    aws_setup = load_aws_cli_setup(server_name)
    
    return render_template('server_settings.html',
                          server=data["servers"][server_name],
                          aws_installed=aws_installed,
                          aws_setup=aws_setup,
                          is_admin=session.get('is_admin', False))

@app.route('/server/<server_name>/config/save', methods=['POST'])
@login_required
@admin_required
def save_server_config(server_name):
    config_type = request.form['config_type']
    config_data = request.form['config_data']
    
    success, message = edit_server_config(server_name, config_type, config_data)
    
    if success:
        flash(message, 'success')
        logger.info(f"User {session.get('username')} updated {config_type} configuration for server {server_name}")
    else:
        flash(message, 'danger')
        logger.warning(f"Failed to update {config_type} configuration for server {server_name}: {message}")
    
    return redirect(url_for('server_config', server_name=server_name))

@app.route('/server/<server_name>/clear_logs', methods=['POST'])
@login_required
@admin_required
def clear_server_logs(server_name):
   # Check if server exists
    data = load_servers()
    if server_name not in data["servers"]:
        logger.warning(f"Log clear attempt on non-existent server: {server_name}")
        return jsonify({"success": False, "message": "Server not found"}), 404
    
    # Only clear the webbase log file but add a record of the clear operation
    logs_path = f'/home/{server_name}/Zomboid/server-console.txt'
    webbase_log_path = f'/home/{server_name}/Zomboid/server-console-webbase.txt'
    
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        username = session.get('username', 'unknown')
        clear_message = f"[{timestamp}] [SYSTEM] Logs cleared by user: {username}\n"
        
        # Clear the webbase log and write the clear message
        if os.path.exists(webbase_log_path):
            with open(webbase_log_path, 'w') as f:
                f.write(clear_message)
        
        logger.info(f"User {username} cleared logs for server {server_name}")
        return jsonify({"success": True, "message": "Webbase logs cleared"})
    except Exception as e:
        logger.error(f"Error clearing logs for server {server_name}: {str(e)}")
        return jsonify({"success": False, "message": f"Error clearing logs: {e}"}), 500

@app.route('/terminal/<server_name>')
@login_required
@admin_required
def terminal_view(server_name):
    """Generate a terminal view for the server"""
    # Check if screen session exists for this server
    check_cmd = f"screen -list | grep {server_name}"
    result = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    session_found = result.returncode == 0
    
    return render_template('terminal.html', 
                          server_name=server_name,
                          session_found=session_found)

@app.route('/api/server/<server_name>/terminal-command', methods=['POST'])
@login_required
@admin_required
def terminal_command(server_name):
    """Execute a command in the server's screen session"""
    command = request.json.get('command', '')
    
    # Check if screen session exists
    check_cmd = f"screen -list | grep {server_name}"
    result = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if result.returncode != 0:
        return jsonify({"success": False, "message": "No active screen session"})
    
    # Get screen session ID
    session_id = None
    for line in result.stdout.decode('utf-8').strip().split('\n'):
        if server_name in line:
            parts = line.strip().split('\t')
            if len(parts) > 0:
                session_id = parts[0].strip()
                break
    
    if not session_id:
        return jsonify({"success": False, "message": "Could not identify screen session"})
    
    # Send command to the screen session
    send_cmd = f"screen -S {session_id} -X stuff '{command}\\n'"
    try:
        subprocess.run(send_cmd, shell=True, check=True)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# Streaming Routes
@app.route('/api/server-status-stream')
@login_required
def server_status_stream():
    """Stream server statuses in real-time using Server-Sent Events (SSE)"""
    
    def generate():
        last_check = time.time()
        last_statuses = {}
        
        while True:
            try:
                # Send heartbeat every 30 seconds
                current_time = time.time()
                if current_time - last_check > 30:
                    yield f"event: heartbeat\ndata: {current_time}\n\n"
                    last_check = current_time
                
                # Get all server statuses
                data = load_servers()
                statuses = {}
                status_changed = False
                
                for server_name in data["servers"]:
                    current_status = get_server_status(server_name)
                    statuses[server_name] = current_status
                    # Update in local data
                    data["servers"][server_name]["status"] = current_status
                    
                    # Check if status changed
                    if server_name not in last_statuses or last_statuses[server_name] != current_status:
                        status_changed = True
                
                # Save updated statuses to database
                save_servers(data)
                
                # Only send update if status changed or 5 seconds passed
                if status_changed or current_time - last_check > 5:
                    yield f"event: status_update\ndata: {json.dumps({'statuses': statuses})}\n\n"
                    last_statuses = statuses.copy()
                    last_check = current_time
                
                # Sleep for a reasonable interval
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error in status stream: {str(e)}")
                yield f"event: error\ndata: {str(e)}\n\n"
                time.sleep(10)  # Wait longer after an error
    
    return Response(generate(), 
                   mimetype="text/event-stream",
                   headers={
                       'Cache-Control': 'no-cache',
                       'X-Accel-Buffering': 'no', 
                       'Connection': 'keep-alive'
                   })

@app.route('/api/creation-sessions-stream')
@login_required
def creation_sessions_stream():
    """Stream server creation sessions in real-time using SSE"""
    
    def generate():
        last_data = None
        
        while True:
            try:
                # Get current creation sessions
                data = load_creation_sessions()
                sessions = []
                
                for creation_id, session_data in data["sessions"].items():
                    session_info = session_data.copy()
                    session_info['creation_id'] = creation_id
                    sessions.append(session_info)
                
                # Sort by started_at timestamp (newest first)
                sessions.sort(key=lambda x: x.get('started_at', 0), reverse=True)
                
                # Convert to JSON string
                json_data = json.dumps({"sessions": sessions})
                
                # Only send if data has changed
                if json_data != last_data:
                    yield f"event: sessions_update\ndata: {json_data}\n\n"
                    last_data = json_data
                
                # Add heartbeat every 30 seconds
                yield f"event: heartbeat\ndata: {time.time()}\n\n"
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in creation sessions stream: {str(e)}")
                yield f"event: error\ndata: {str(e)}\n\n"
                time.sleep(10)  # Wait longer after an error
    
    return Response(generate(), 
                   mimetype="text/event-stream",
                   headers={
                       'Cache-Control': 'no-cache',
                       'X-Accel-Buffering': 'no', 
                       'Connection': 'keep-alive'
                   })

# Player Management Routes
@app.route('/api/server/<server_name>/ban-player', methods=['POST'])
@login_required
@admin_required
def api_ban_player(server_name):
   """API endpoint to ban a player"""
   data = request.json
   username = data.get('username')
   steam_id = data.get('steam_id')
   ip = data.get('ip')
   reason = data.get('reason', '')
   duration = data.get('duration', 'permanent')
   admin_name = session.get('username', 'unknown')
   
   if not username:
       return jsonify({"success": False, "message": "Username is required"}), 400
   
   try:
       # We'll just add the player to the database
       # The actual command execution will happen client-side via JavaScript
       
       # Add to our ban database regardless of server status
       add_banned_player(server_name, username, steam_id, ip, reason, duration, admin_name)
       
       logger.info(f"Player {username} banned from server {server_name} by admin {admin_name}")
       return jsonify({"success": True, "message": f"Player {username} has been banned"})
   except Exception as e:
       logger.error(f"Error banning player {username} from server {server_name}: {str(e)}")
       return jsonify({"success": False, "message": f"Error banning player: {str(e)}"}), 500

@app.route('/api/server/<server_name>/unban-player', methods=['POST'])
@login_required
@admin_required
def api_unban_player(server_name):
   """API endpoint to unban a player"""
   data = request.json
   username = data.get('username')
   
   if not username:
       return jsonify({"success": False, "message": "Username is required"}), 400
   
   try:
       # We'll just remove the player from the database
       # The actual command execution will happen client-side via JavaScript
       
       # Remove from our ban database regardless of server status
       remove_banned_player(server_name, username)
       
       admin_name = session.get('username', 'unknown')
       logger.info(f"Player {username} unbanned from server {server_name} by admin {admin_name}")
       return jsonify({"success": True, "message": f"Player {username} has been unbanned"})
   except Exception as e:
       logger.error(f"Error unbanning player {username} from server {server_name}: {str(e)}")
       return jsonify({"success": False, "message": f"Error unbanning player: {str(e)}"}), 500

@app.route('/api/server/<server_name>/banned-players')
@login_required
def get_server_banned_players(server_name):
   """API endpoint to get banned players for a server"""
   # Check if server exists
   data = load_servers()
   if server_name not in data["servers"]:
       logger.warning(f"Banned player list requested for non-existent server: {server_name}")
       return jsonify({"success": False, "message": "Server not found"}), 404
   
   try:
       banned_players = get_banned_players(server_name)
       
       # Convert timestamps to human-readable format
       for player in banned_players:
           if "banned_at" in player:
               player["banned_at_formatted"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(player["banned_at"]))
           
           if "expiry" in player and player["expiry"]:
               player["expiry_formatted"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(player["expiry"]))
               # Calculate time remaining
               remaining_seconds = max(0, player["expiry"] - int(time.time()))
               days, remainder = divmod(remaining_seconds, 86400)
               hours, remainder = divmod(remainder, 3600)
               minutes, _ = divmod(remainder, 60)
               
               if days > 0:
                   player["time_remaining"] = f"{days}d {hours}h {minutes}m"
               elif hours > 0:
                   player["time_remaining"] = f"{hours}h {minutes}m"
               else:
                   player["time_remaining"] = f"{minutes}m"
           else:
               player["time_remaining"] = "Permanent"
       
       logger.debug(f"Retrieved {len(banned_players)} banned players for server {server_name}")
       return jsonify({
           "success": True, 
           "banned_players": banned_players
       })
   except Exception as e:
       logger.error(f"Error retrieving banned players for server {server_name}: {str(e)}")
       return jsonify({"success": False, "message": f"Error retrieving banned players: {str(e)}"}), 500

# Advanced File Routes
@app.route('/api/server/<server_name>/search')
@login_required
def api_search_files(server_name):
    """API endpoint to search for files and folders"""
    search_term = request.args.get('term', '')
    case_sensitive = request.args.get('case_sensitive', 'false').lower() == 'true'
    
    if not search_term:
        return jsonify({"success": False, "message": "Search term is required"}), 400
    
    # Base directory to search in
    base_dir = f'/home/{server_name}/'
    
    # Security check
    if not os.path.exists(base_dir):
        logger.warning(f"Search attempt on non-existent server directory: {base_dir}")
        return jsonify({"success": False, "message": "Server directory not found"}), 404
    
    try:
        results = {
            "files": [],
            "folders": []
        }
        
        # Prepare search term based on case sensitivity
        if not case_sensitive:
            search_term = search_term.lower()
        
        # Maximum results to return (to prevent overwhelming response)
        max_results = 100
        total_results = 0
        
        # Walk through the directory tree
        for root, dirs, files in os.walk(base_dir):
            # Skip hidden directories and sensitive paths
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['lost+found']]
            
            # Check folder names
            for dirname in dirs:
                # Check if we've reached the maximum results
                if total_results >= max_results:
                    break
                
                # Convert to lowercase if case-insensitive search
                check_name = dirname if case_sensitive else dirname.lower()
                
                if search_term in check_name:
                    folder_path = os.path.join(root, dirname)
                    rel_path = os.path.relpath(folder_path, base_dir)
                    results["folders"].append({
                        "name": dirname,
                        "path": os.path.join(base_dir, rel_path)
                    })
                    total_results += 1
            
            # Check file names
            for filename in files:
                # Skip hidden files
                if filename.startswith('.'):
                    continue
                
                # Check if we've reached the maximum results
                if total_results >= max_results:
                    break
                
                # Convert to lowercase if case-insensitive search
                check_name = filename if case_sensitive else filename.lower()
                
                if search_term in check_name:
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, base_dir)
                    results["files"].append({
                        "name": filename,
                        "path": os.path.join(base_dir, rel_path)
                    })
                    total_results += 1
        
        # Sort results alphabetically
        results["folders"].sort(key=lambda x: x["name"].lower())
        results["files"].sort(key=lambda x: x["name"].lower())
        
        logger.info(f"User {session.get('username')} searched for '{search_term}' in server {server_name}, found {total_results} results")
        
        # If maximum results were reached, add a note
        reached_limit = total_results >= max_results
        
        return jsonify({
            "success": True, 
            "results": results,
            "reached_limit": reached_limit,
            "total_results": total_results
        })
    except Exception as e:
        logger.error(f"Error searching files for server {server_name}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/<server_name>/download')
@login_required
def api_download_file(server_name):
    """API endpoint to download a file"""
    path = request.args.get('path')
    
    if not path:
        return jsonify({"success": False, "message": "Path parameter is required"}), 400
    
    # Security check
    if not path.startswith(f'/home/{server_name}/'):
        logger.warning(f"Security: Attempted file download outside server directory by user {session.get('username')}")
        return jsonify({"success": False, "message": "Security violation: Access denied"}), 403
    
    try:
        # Check if file exists
        if not os.path.exists(path) or os.path.isdir(path):
            return jsonify({"success": False, "message": "File not found"}), 404
        
        # Log download activity
        logger.info(f"User {session.get('username')} downloaded file {path}")
        
        # Return the file for download
        return send_file(path, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading file {path}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/<server_name>/zip', methods=['POST'])
@login_required
def api_create_zip(server_name):
    """API endpoint to create a ZIP archive of files/folders"""
    data = request.json
    paths = data.get('paths', [])
    
    if not paths:
        return jsonify({"success": False, "message": "Paths parameter is required"}), 400
    
    # Convert single path to list
    if isinstance(paths, str):
        paths = [paths]
    
    # Security check for all paths
    for path in paths:
        if not path.startswith(f'/home/{server_name}/'):
            logger.warning(f"Security: Attempted ZIP creation outside server directory by user {session.get('username')}")
            return jsonify({"success": False, "message": "Security violation: Access denied"}), 403
    
    try:
        # Create in-memory ZIP file
        memory_file = io.BytesIO()
        
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add each requested path to the ZIP
            for path in paths:
                if os.path.isdir(path):
                    # For directories, add recursively
                    base_path = os.path.dirname(path)
                    dir_name = os.path.basename(path)
                    
                    for root, dirs, files in os.walk(path):
                        # Skip hidden files/dirs
                        files = [f for f in files if not f.startswith('.')]
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        
                        for file in files:
                            file_path = os.path.join(root, file)
                            # Calculate relative path for the archive
                            rel_path = os.path.join(dir_name, os.path.relpath(file_path, path))
                            zf.write(file_path, rel_path)
                else:
                    # For files, add directly
                    zf.write(path, os.path.basename(path))
        
        # Seek to the beginning of the file
        memory_file.seek(0)
        
        # Determine ZIP filename based on what's being zipped
        if len(paths) == 1:
            zip_name = os.path.basename(paths[0]) + '.zip'
        else:
            zip_name = f"{server_name}_files.zip"
        
        logger.info(f"User {session.get('username')} created ZIP archive containing {len(paths)} paths")
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=zip_name
        )
    except Exception as e:
        logger.error(f"Error creating ZIP archive: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

# AWS/Backup Routes
@app.route('/server/<server_name>/aws-config', methods=['POST'])
@login_required
@admin_required
def save_aws_config(server_name):
    """Save AWS CLI configuration for R2 or S3-compatible storage"""
    config_file = f'aws_cli_setup_{server_name}.json'
    
    # Get form data
    access_key = request.form.get('access_key', '')
    secret_key = request.form.get('secret_key', '')
    region = request.form.get('region', 'auto')
    output_format = request.form.get('output_format', 'json')
    endpoint_url = request.form.get('endpoint_url', '')
    profile_name = request.form.get('profile_name', 'r2')
    
    # Load existing config
    aws_setup = load_aws_cli_setup(server_name)
    
    # Update config
    aws_setup["setup_enabled"] = True
    aws_setup["access_key_id"] = access_key
    aws_setup["secret_access_key"] = secret_key
    aws_setup["region"] = region
    aws_setup["output_format"] = output_format
    aws_setup["endpoint_url"] = endpoint_url
    aws_setup["profile_name"] = profile_name
    
    # Save config
    with open(config_file, 'w') as f:
        json.dump(aws_setup, f, indent=4)
    
    # Configure AWS CLI with profile
    try:
        # Create AWS config command with profile
        aws_config_cmd = f"""
aws configure set aws_access_key_id {access_key} --profile {profile_name}
aws configure set aws_secret_access_key {secret_key} --profile {profile_name}
aws configure set region {region} --profile {profile_name}
aws configure set output {output_format} --profile {profile_name}
"""
        # Add endpoint URL if provided
        if endpoint_url:
            aws_config_cmd += f"aws configure set endpoint_url {endpoint_url} --profile {profile_name}\n"
            
        # Execute AWS config
        result = subprocess.run(aws_config_cmd, shell=True, check=True, capture_output=True)
        
        # Mark as completed
        aws_setup["is_completed"] = True
        with open(config_file, 'w') as f:
            json.dump(aws_setup, f, indent=4)
        
        flash('S3 credentials configured successfully', 'success')
        logger.info(f"User {session.get('username')} configured S3 credentials for server {server_name}")
    except subprocess.CalledProcessError as e:
        flash(f'Error configuring S3 credentials: {e.stderr.decode()}', 'danger')
        logger.error(f"Error configuring S3 credentials for server {server_name}: {e.stderr.decode()}")
    
    return redirect(url_for('server_settings', server_name=server_name))

@app.route('/server/<server_name>/backup-config', methods=['POST'])
@login_required
@admin_required
def save_backup_config(server_name):
    """Save backup configuration"""
    # Get form data
    bucket_name = request.form.get('bucket_name', '')
    backup_enabled = 'backup_enabled' in request.form
    backup_schedule_type = request.form.get('backup_schedule_type', 'interval')
    retention_count = int(request.form.get('retention_count', 10))
    backup_items = request.form.getlist('backup_items')
    
    # Schedule-specific parameters
    schedule_params = {}
    
    if backup_schedule_type == 'interval':
        schedule_params['interval_value'] = request.form.get('interval_value', '3')
        schedule_params['interval_unit'] = request.form.get('interval_unit', 'hours')
    
    elif backup_schedule_type == 'fixed':
        schedule_params['fixed_time'] = request.form.get('fixed_time', '04:00')
        schedule_params['fixed_days'] = request.form.getlist('fixed_days') or ['mon', 'wed', 'fri']
    
    elif backup_schedule_type == 'custom':
        schedule_params['cron_expression'] = request.form.get('cron_expression', '0 4 * * *')
    
    # Build backup configuration
    backup_config = {
        'bucket_name': bucket_name,
        'backup_enabled': backup_enabled,
        'backup_schedule_type': backup_schedule_type,
        'retention_count': retention_count,
        'backup_items': backup_items,
        **schedule_params
    }
    
    # Update configuration
    success, message = update_aws_backup_schedule(server_name, backup_config)
    
    # Handle immediate backup if requested
    if 'run_backup_now' in request.form and success:
        backup_success, backup_message = run_backup_now(server_name)
        if backup_success:
            flash(f"Configuration saved and backup executed successfully", 'success')
        else:
            flash(f"Configuration saved but backup failed: {backup_message}", 'warning')
    # Test backup if requested
    elif 'test_backup' in request.form and success:
        test_success, test_message = test_backup(server_name, load_aws_cli_setup(server_name))
        if test_success:
            flash(f"Configuration saved and test successful: {test_message}", 'success')
        else:
            flash(f"Configuration saved but test failed: {test_message}", 'warning')
    else:
        if success:
            flash('Backup configuration saved successfully', 'success')
        else:
            flash(f'Error saving backup configuration: {message}', 'danger')
    
    logger.info(f"User {session.get('username')} configured backup settings for server {server_name}")
    return redirect(url_for('server_settings', server_name=server_name))

def test_backup(server_name, aws_setup):
    """Test backup configuration by creating a small test file and uploading to S3"""
    try:
        # Create a test file
        test_file = f'/tmp/pz_backup_test_{server_name}.txt'
        with open(test_file, 'w') as f:
            f.write(f"Project Zomboid backup test for server {server_name}")
        
        # Upload to S3
        bucket = aws_setup["bucket_name"]
        test_key = f'test/pz_backup_test_{server_name}.txt'
        profile_name = aws_setup.get("profile_name", "r2")
        
        # Build command with endpoint URL if provided
        if aws_setup.get("endpoint_url"):
            upload_cmd = f'aws s3 cp {test_file} s3://{bucket}/{test_key} --profile {profile_name} --endpoint-url {aws_setup["endpoint_url"]}'
        else:
            upload_cmd = f'aws s3 cp {test_file} s3://{bucket}/{test_key} --profile {profile_name}'
            
        result = subprocess.run(upload_cmd, shell=True, check=True, capture_output=True)
        
        return True, "Backup test successful! Test file uploaded to S3 bucket."
    except subprocess.CalledProcessError as e:
        logger.error(f"Backup test failed for server {server_name}: {e.stderr.decode()}")
        return False, f"Backup test failed: {e.stderr.decode()}"
    except Exception as e:
        logger.error(f"Backup test exception for server {server_name}: {str(e)}")
        return False, f"Backup test failed: {str(e)}"

def run_backup_now(server_name):
    """Run backup script immediately"""
    try:
        script_path = f'/home/{server_name}/backup_script.sh'
        
        # Check if script exists
        if not os.path.exists(script_path):
            logger.info(f"Backup script not found for {server_name}, creating it now")
            aws_setup = load_aws_cli_setup(server_name)
            script_content = generate_backup_script(server_name, aws_setup)
            
            # Missing: Write script_content to file
            with open(script_path, 'w') as f:
                f.write(script_content)
            logger.info(f"Created backup script at {script_path}")
        
        # Make executable
        subprocess.run(['sudo', 'chmod', '+x', script_path], check=True)
        
        # Execute script
        subprocess.run(script_path, shell=True, check=True)
        
        logger.info(f"Running backup script for {server_name}")
        cmd = f"sudo -u {server_name} bash -l -c '{script_path}'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        # Log the backup output
        if result.returncode == 0:
            logger.info(f"Backup completed successfully for server {server_name}")
            return True, "Backup completed successfully"
        else:
            logger.error(f"Backup failed for server {server_name} with code {result.returncode}: {result.stderr}")
            return False, f"Backup failed with code {result.returncode}: {result.stderr}"
    except subprocess.TimeoutExpired:
        logger.error(f"Backup timed out for server {server_name}")
        return False, "Backup timed out after 5 minutes"
    except Exception as e:
        logger.error(f"Error running backup for server {server_name}: {str(e)}")
        return False, f"Error running backup: {str(e)}"

def remove_backup_cron(server_name):
    """Remove existing backup cron jobs for a server"""
    try:
        # Get current crontab content
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if result.returncode == 0:
            cron_content = result.stdout
        else:
            # No existing crontab, nothing to remove
            return True
        
        # Remove any jobs with matching comment
        new_content_lines = []
        for line in cron_content.splitlines():
            if f"pz_backup_{server_name}" not in line:
                new_content_lines.append(line)
        
        # Write the new crontab
        new_content = "\n".join(new_content_lines) + "\n"
        with open('/tmp/new_crontab', 'w') as f:
            f.write(new_content)
        
        # Install the new crontab
        install_result = subprocess.run(['crontab', '/tmp/new_crontab'], capture_output=True, text=True, check=True)
        
        logger.info(f"Removed existing backup cron jobs for server {server_name}")
        return True
    except Exception as e:
        logger.error(f"Error removing backup cron for server {server_name}: {str(e)}")
        return False

def setup_backup_cron(server_name, script_path, aws_setup):
    """Setup cron job for backup script based on schedule settings - direct file approach"""
    try:
        # Get current crontab content for the current user (not the server user)
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if result.returncode == 0:
            cron_content = result.stdout
        else:
            cron_content = ""
        
        # Remove any existing backup jobs for this server
        new_content_lines = []
        for line in cron_content.splitlines():
            if f"pz_backup_{server_name}" not in line:
                new_content_lines.append(line)
        
        # Create new cron entry
        schedule_type = aws_setup.get('backup_schedule_type', 'interval')
        cron_schedule = ""
        
        if schedule_type == 'interval':
            # Interval-based schedule
            interval_value = int(aws_setup.get('interval_value', 3))
            interval_unit = aws_setup.get('interval_unit', 'hours')
            
            if interval_unit == 'hours':
                cron_schedule = f"0 */{interval_value} * * *"
            elif interval_unit == 'days':
                cron_schedule = f"0 4 */{interval_value} * *"
            elif interval_unit == 'weeks':
                cron_schedule = f"0 4 * * 1"
        
        elif schedule_type == 'fixed':
            # Fixed schedule
            fixed_time = aws_setup.get('fixed_time', '04:00')
            hour, minute = fixed_time.split(':')
            
            # Parse selected days, default to Monday, Wednesday, Friday
            fixed_days = aws_setup.get('fixed_days', ['mon', 'wed', 'fri'])
            if not fixed_days:
                fixed_days = ['mon', 'wed', 'fri']
                
            # Convert day abbreviations to cron format
            day_map = {'mon': '1', 'tue': '2', 'wed': '3', 'thu': '4', 'fri': '5', 'sat': '6', 'sun': '0'}
            cron_days = ','.join([day_map[day] for day in fixed_days if day in day_map])
            
            cron_schedule = f"{minute} {hour} * * {cron_days}"
        
        elif schedule_type == 'custom':
            # Custom cron expression
            cron_schedule = aws_setup.get('cron_expression', '0 4 * * *')
        
        # Add new cron job - use sudo to run script as server user
        cron_job = f"{cron_schedule} {script_path} # pz_backup_{server_name}"
        new_content_lines.append(cron_job)
        
        # Write the new crontab
        new_content = "\n".join(new_content_lines) + "\n"
        with open('/tmp/new_crontab', 'w') as f:
            f.write(new_content)
        
        # Install the new crontab
        install_result = subprocess.run(['crontab', '/tmp/new_crontab'], capture_output=True, text=True, check=True)
        
        logger.info(f"Backup cron job set up for server {server_name} with schedule: {cron_schedule}")
        logger.debug(f"New crontab content:\n{new_content}")
        return True
    except Exception as e:
        logger.error(f"Error setting up backup cron for server {server_name}: {str(e)}")
        return False
   
def load_aws_cli_setup(server_name):
    """Load AWS CLI setup information for a server"""
    config_file = f'aws_cli_setup_{server_name}.json'
    
    if not os.path.exists(config_file):
        # Create default config
        default_config = {
            "setup_enabled": False,
            "is_completed": False,
            "access_key_id": "",
            "secret_access_key": "",
            "region": "",
            "output_format": "json",
            "bucket_name": "",
            "backup_enabled": False,
            "backup_frequency": "daily",
            "backup_items": ["world", "config"]
        }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        
        return default_config
    
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except:
        return {
            "setup_enabled": False,
            "is_completed": False,
            "access_key_id": "",
            "secret_access_key": "",
            "region": "",
            "output_format": "json",
            "bucket_name": "",
            "backup_enabled": False,
            "backup_frequency": "daily",
            "backup_items": ["world", "config"]
        }

def is_aws_cli_installed():
    """Check if AWS CLI is installed on the system"""
    try:
        result = subprocess.run(['aws', '--version'], 
                              capture_output=True, 
                              text=True)
        return result.returncode == 0
    except:
        return False

# Initialize users
init_users_file()

# Log application startup
logger.info("Project Zomboid Server Manager started")

if __name__ == '__main__':
    initiate_first_load()
    app.run(host='0.0.0.0', port=5000, debug=True)