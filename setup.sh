#!/bin/bash

# Function to check if the script is running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit 1
    fi
}

# Function to determine the Linux distribution
get_distribution() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    elif [ -f /etc/centos-release ]; then
        DISTRO="centos"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
}

# Function to add a user and add it to the sudo group
add_user() {
    useradd -m -s /bin/bash agent
    if [ $? -eq 0 ]; then
        echo "User 'agent' created successfully"
    else
        echo "User 'agent' already exists or error occurred"
    fi
    
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        usermod -aG sudo agent
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        usermod -aG wheel agent
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
    echo "User 'agent' added to sudo group"
}

# Function to configure SSH settings
configure_ssh() {
    sed -i 's/^#Port 22/Port 24682/' /etc/ssh/sshd_config
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# Function to update and upgrade the system
update_upgrade() {
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        apt update && apt upgrade -y
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        yum update -y && yum upgrade -y
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
}

# Function to install necessary packages
install_packages() {
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        apt install -y git tmux tor htop
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        yum install -y git tmux tor htop
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
}

# Main script execution
check_root
get_distribution
add_user
configure_ssh
update_upgrade
install_packages

echo "Setup completed successfully."
