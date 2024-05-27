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

# Function to update and upgrade the system
update_upgrade() {
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        apt update && apt upgrade -y
        apt install -y unattended-upgrades
        dpkg-reconfigure --priority=low unattended-upgrades
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        yum update -y && yum upgrade -y
        yum install -y yum-cron
        systemctl start yum-cron
        systemctl enable yum-cron
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
}

# Function to install necessary packages
install_packages() {
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        apt install -y git tmux tor htop ufw fail2ban logrotate rsyslog
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        yum install -y git tmux tor htop firewalld epel-release fail2ban logrotate rsyslog
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
}

# Function to add a user and add it to the sudo group
add_user() {
    if id "agent" &>/dev/null; then
        echo "User 'agent' already exists"
    else
        useradd -m -s /bin/bash agent
        echo "User 'agent' created successfully"
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
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

    # Generate SSH keys for the 'agent' user
    sudo -u agent ssh-keygen -t ed25519 -f /home/agent/.ssh/id_ed25519 -N "" || { echo "SSH key generation failed"; exit 1; }

    # Add the public key to authorized_keys
    cat /home/agent/.ssh/id_ed25519.pub >> /home/agent/.ssh/authorized_keys
    
    # Adjust permissions
    chown -R agent:agent /home/agent/.ssh
    chmod 700 /home/agent/.ssh
    chmod 600 /home/agent/.ssh/authorized_keys

    systemctl restart sshd
}

# Function to configure firewall
configure_firewall() {
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        ufw allow 24682/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw --force enable
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --permanent --add-port=24682/tcp
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
}

# Function to install Fail2Ban
install_fail2ban() {
    systemctl start fail2ban
    systemctl enable fail2ban
}

# Function to configure system logging
configure_logging() {
    systemctl enable rsyslog
    systemctl start rsyslog
}

# Function to configure swap space
configure_swap() {
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
}

# Function to export SSH keys to GitHub private repository
export_keys_to_github() {
    # Ensure the agent's public/private key exists
    if [ ! -f /home/agent/.ssh/id_ed25519 ]; then
        echo "SSH keys for user 'agent' not found."
        return 1
    fi

    # Set your GitHub repository details here
    GITHUB_REPO_URL="https://github.com/dukeofam/ServerSetup.git"
    LOCAL_REPO_DIR="/tmp/ssh-keys-backup"

    # Clone the repository
    git clone "$GITHUB_REPO_URL" "$LOCAL_REPO_DIR"

    # Copy SSH keys to the repository directory
    cp /home/agent/.ssh/id_ed25519 "$LOCAL_REPO_DIR/"
    cp /home/agent/.ssh/id_ed25519.pub "$LOCAL_REPO_DIR/"

    # Commit and push the changes
    cd "$LOCAL_REPO_DIR"
    git add id_ed25519 id_ed25519.pub
    git commit -m "Add new SSH keys for agent"
    git push origin main

    # Clean up
    rm -rf "$LOCAL_REPO_DIR"
}

# Main script execution
check_root
get_distribution
update_upgrade
install_packages
add_user
configure_ssh
configure_firewall
install_fail2ban
configure_logging
configure_swap

echo "Setup completed successfully."
