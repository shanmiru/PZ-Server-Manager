# Tempest PZ Manager

## 📊 Project Status
**Current Version:** `v0.1.0 - Early Development`


This server manager was made by an _inexperienced_ developer, so feel free to request any functions you would like added in the future. 
This is not the _final_ version of this PZ server manager; I am just starting. 
Found a bug? Try fixing the code yourself or put it on the "_Issues_" page so I can look it up when I have some time.

## Dashboard:

![PZ Manager Dashboard](https://i.imgur.com/4vjzfT8.png)

## Dashboard->ServerStats:
![PZ Manager ServerStatus](https://i.imgur.com/gOSOxqA.png)

## Dashboard->SampleCard:
![PZ manager SampleCard](https://i.imgur.com/5e93Pff.png)

## Overview
Project Zomboid Linux/Ubuntu Server Manager (shanmiru) a dashboard for manage Project Zomboid server on Linux/Ubuntu.

Tempest PZ Manager is a full-featured web interface for creating, managing, and monitoring Project Zomboid dedicated servers. Built with Flask and Bootstrap, it provides an intuitive, responsive dashboard that simplifies server administration tasks.

## Features

### Server Management
- **One-Click Operations**: Start, stop, and restart servers with a single click
- **Real-Time Monitoring**: View CPU, memory, disk, and network usage stats
- **Terminal Access**: Direct access to server console and commands
- **Player Management**: Ban/unban, kick, and teleport players
- **File Manager**: Browse, edit, and upload server files

### Server Creation
- **Easy Setup**: Create new Project Zomboid servers in minutes
- **Automatic Configuration**: Ports, firewall rules, and system users configured automatically
- **Live Creation Logs**: Real-time feedback during server creation
- **Customizable Settings**: Control admin password, server password, and ports

### Backup System
- **Cloud Storage Support**: Back up to S3-compatible storage (including Cloudflare R2)
- **Scheduled Backups**: Configure backup frequency and retention policies
- **AutoRestart**: (Disabled and removed) wait for new patch
- **One-Click Restoration**: Easily restore from backups (Beta this needs a terminal knowledge)

### User Management
- **Multi-User Support**: Create administrator and regular user accounts
- **Secure Authentication**: Password-protected access to the management interface ( I kind of used SHA256, found a way to refine it, and made it more robust? send it to me so I can implement it in the next patch? )

### Security Features
- **Firewall Management**: Automatic firewall configuration for each server
- **Password Protection**: Secure admin and RCON passwords
- **Access Control**: Granular permission system for users

## Requirements

- Ubuntu/Debian Linux system (tested on Ubuntu 20.04+)
- Python 3.8 or higher
- Flask and dependencies (see requirements.txt)
- AWS CLI (for backup functionality)

## Must Read!!
- I tested this on Ubuntu 22.04 and perfectly fine.

## Installation

**Must do first**:
```bash
apt-get update
apt install python3-pip -y
```

```bash
# Clone the repository
git clone https://github.com/shanmiru/PZ-Server-Manager.git
cd PZ-Server-Manager

# Install dependencies
pip install -r req.txt

# Run the application
python3 app.py or python app.py
```

## Support the Project
If you find this project helpful and want to show your appreciation, you can support me through PayPal

![Paypal](https://i.imgur.com/l04Zf8p.png)

Donation Email: ``yieshaforstirling@gmail.com`` or ``paypal.me/dazaikun45``
Your support helps me continue developing and improving this project. Every contribution, no matter how small, is greatly appreciated! 🙏
