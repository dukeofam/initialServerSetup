#!/bin/bash

LOGFILE="/var/log/server_setup.log"
exec > >(tee -i $LOGFILE)
exec 2>&1

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
    read -p "Enter the username to create: " USERNAME
    if id "$USERNAME" &>/dev/null; then
        echo "User '$USERNAME' already exists"
    else
        useradd -m -s /bin/bash "$USERNAME"
        echo "User '$USERNAME' created successfully"
    fi

    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        usermod -aG sudo "$USERNAME"
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        usermod -aG wheel "$USERNAME"
    else
        echo "Unsupported Linux distribution"
        exit 1
    fi
    echo "User '$USERNAME' added to sudo group"
}

# Function to configure SSH settings
configure_ssh() {
    read -p "Enter the custom SSH port: " SSH_PORT

    echo "Choose the SSH encryption algorithm:"
    echo "1) RSA (4096 bits)"
    echo "2) ECDSA (521 bits)"
    echo "3) ED25519"
    read -p "Enter the number corresponding to your choice: " ALGO_CHOICE

    case $ALGO_CHOICE in
        1)
            SSH_ALGO="rsa"
            SSH_KEY_BITS=4096
            ;;
        2)
            SSH_ALGO="ecdsa"
            SSH_KEY_BITS=521
            ;;
        3)
            SSH_ALGO="ed25519"
            SSH_KEY_BITS=""
            ;;
        *)
            echo "Invalid choice. Defaulting to ED25519."
            SSH_ALGO="ed25519"
            SSH_KEY_BITS=""
            ;;
    esac

    SSH_KEY_FILE="/home/$USERNAME/.ssh/id_$SSH_ALGO"
    
    sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

    # Generate SSH keys for the user
    if [ -n "$SSH_KEY_BITS" ]; then
        sudo -u "$USERNAME" ssh-keygen -t "$SSH_ALGO" -b "$SSH_KEY_BITS" -f "$SSH_KEY_FILE" -N "" || { echo "SSH key generation failed"; exit 1; }
    else
        sudo -u "$USERNAME" ssh-keygen -t "$SSH_ALGO" -f "$SSH_KEY_FILE" -N "" || { echo "SSH key generation failed"; exit 1; }
    fi

    # Add the public key to authorized_keys
    cat "$SSH_KEY_FILE.pub" >> "/home/$USERNAME/.ssh/authorized_keys"
    
    # Adjust permissions
    chown -R "$USERNAME":"$USERNAME" "/home/$USERNAME/.ssh"
    chmod 700 "/home/$USERNAME/.ssh"
    chmod 600 "/home/$USERNAME/.ssh/authorized_keys"

    systemctl restart sshd
}

# Function to configure firewall
configure_firewall() {
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        ufw default deny incoming
        ufw default allow outgoing

        read -p "Enter the custom SSH port: " SSH_PORT
        read -p "Enter IP address to allow access for SSH port $SSH_PORT (or leave empty to allow from all IPs): " SSH_IP
        if [ -n "$SSH_IP" ]; then
            ufw allow from "$SSH_IP" to any port "$SSH_PORT"/tcp
        else
            ufw allow "$SSH_PORT"/tcp
        fi

        declare -A FIREWALL_PORTS

        while true; do
            read -p "Enter a port to configure (or 'done' to finish): " PORT
            [[ $PORT == "done" ]] && break
            read -p "Enter IP address to allow access for port $PORT (or leave empty to allow from all IPs): " IP_ADDRESS
            if [ -n "$IP_ADDRESS" ]; then
                read -p "Do you want to allow or deny access for port $PORT from IP $IP_ADDRESS? (allow/deny): " ACTION
                FIREWALL_PORTS[$PORT]=$ACTION
            fi
        done

        for PORT in "${!FIREWALL_PORTS[@]}"; do
            ufw "${FIREWALL_PORTS[$PORT]}" from "$IP_ADDRESS" to any port "$PORT"/tcp
        done

        ufw --force enable
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        systemctl start firewalld
        systemctl enable firewalld

        firewall-cmd --set-default-zone=drop
        firewall-cmd --permanent --zone=drop --add-interface=eth0

        read -p "Enter the custom SSH port: " SSH_PORT
        read -p "Enter IP address to allow access for SSH port $SSH_PORT (or leave empty to allow from all IPs): " SSH_IP
        if [ -n "$SSH_IP" ]; then
            firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address='"$SSH_IP"' accept' --destination-port="$SSH_PORT"/tcp
        else
            firewall-cmd --permanent --add-port="$SSH_PORT"/tcp
        fi

        declare -A FIREWALL_PORTS

        while true; do
            read -p "Enter a port to configure (or 'done' to finish): " PORT
            [[ $PORT == "done" ]] && break
            read -p "Enter IP address to allow access for port $PORT (or leave empty to allow from all IPs): " IP_ADDRESS
            if [ -n "$IP_ADDRESS" ]; then
                read -p "Do you want to allow or deny access for port $PORT from IP $IP_ADDRESS? (allow/deny): " ACTION
                FIREWALL_PORTS[$PORT]=$ACTION
            fi
        done

        for PORT in "${!FIREWALL_PORTS[@]}"; do
            firewall-cmd --permanent --"${FIREWALL_PORTS[$PORT]}"-port="$PORT"/tcp
        done

        read -p "Enter IP address to allow access (or leave empty to allow from all IPs): " ALLOWED_IP
        if [ -n "$ALLOWED_IP" ]; then
            firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address='"$ALLOWED_IP"' accept'
        fi

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
    read -p "Enter the swapfile size (e.g., 2G): " SWAP_SIZE
    fallocate -l "$SWAP_SIZE" /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
}

# Function to export SSH keys to GitHub private repository
export_keys_to_github() {
    read -p "Enter your GitHub repository URL: " GITHUB_REPO_URL
    read -p "Enter the local directory to clone the repository [/tmp/ssh-keys-backup]: " LOCAL_REPO_DIR
    LOCAL_REPO_DIR=${LOCAL_REPO_DIR:-/tmp/ssh-keys-backup}

    # Ensure the user's public/private key exists
    if [ ! -f "$SSH_KEY_FILE" ]; then
        echo "SSH keys for user '$USERNAME' not found."
        return 1
    fi

    # Clone the repository
    git clone "$GITHUB_REPO_URL" "$LOCAL_REPO_DIR"

    # Copy SSH keys to the repository directory
    cp "$SSH_KEY_FILE" "$LOCAL_REPO_DIR/"
    cp "$SSH_KEY_FILE.pub" "$LOCAL_REPO_DIR/"

    # Commit and push the changes
    cd "$LOCAL_REPO_DIR"
    git add id_$SSH_ALGO id_$SSH_ALGO.pub
    git commit -m "Add new SSH keys for $USERNAME"
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

# Ask if the user wants to export SSH keys to GitHub
read -p "Do you want to export SSH keys to GitHub? (yes/no): " EXPORT_KEYS
if [ "$EXPORT_KEYS" == "yes" ]; then
    export_keys_to_github
fi
