#!/bin/bash

# Function to check if the script is running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit 1
    fi
}

# Log file location
LOGFILE="/var/log/server_setup.log"

# Redirecting stdout and stderr to the log file
exec > >(tee -i "$LOGFILE")
exec 2>&1

# Configuration file
CONFIG_FILE="config.conf"

# Function to read configuration settings from the file
read_config() {
    # Check if the config file exists
    if [ -f "$CONFIG_FILE" ]; then
        # Read configuration settings from the file
        source "$CONFIG_FILE"
    else
        echo "No config file found. Skipping configuration."
    fi
}

# Function to validate user inputs
validate_input() {
    local prompt="$1"
    local input_var="$2"
    local regex="$3"

    read -p "$prompt" "$input_var"

    if [[ ! ${!input_var} =~ $regex ]]; then
        echo "Invalid input. Please try again."
        validate_input "$prompt" "$input_var" "$regex"
    fi
}

# Function to handle errors gracefully
handle_error() {
    local error_message="$1"
    echo "Error: $error_message" >&2
    exit 1
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
        handle_error "Unsupported Linux distribution"
    fi
}

# Function to update and upgrade the system
update_upgrade() {
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        apt update && apt upgrade -y || handle_error "Failed to update and upgrade system"
        apt install -y unattended-upgrades || handle_error "Failed to install unattended-upgrades"
        dpkg-reconfigure --priority=low unattended-upgrades || handle_error "Failed to reconfigure unattended-upgrades"
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        yum update -y && yum upgrade -y || handle_error "Failed to update and upgrade system"
        yum install -y yum-cron || handle_error "Failed to install yum-cron"
        systemctl start yum-cron || handle_error "Failed to start yum-cron"
        systemctl enable yum-cron || handle_error "Failed to enable yum-cron"
    else
        handle_error "Unsupported Linux distribution"
    fi
}

# Function to install necessary packages
install_packages() {
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        apt install -y git tmux tor htop ufw fail2ban logrotate rsyslog || handle_error "Failed to install packages"
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        yum install -y git tmux tor htop firewalld epel-release fail2ban logrotate rsyslog || handle_error "Failed to install packages"
    else
        handle_error "Unsupported Linux distribution"
    fi
}

# Function to add a user and add it to the sudo group
add_user() {
    local USERNAME
    validate_input "Enter the username to create: " USERNAME '^[a-z_][a-z0-9_-]*[$]?$'

    if id "$USERNAME" &>/dev/null; then
        echo "User '$USERNAME' already exists"
    else
        useradd -m -s /bin/bash "$USERNAME" || handle_error "Failed to create user"
        echo "User '$USERNAME' created successfully"
    fi

    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        usermod -aG sudo "$USERNAME" || handle_error "Failed to add user to sudo group"
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        usermod -aG wheel "$USERNAME" || handle_error "Failed to add user to wheel group"
    else
        handle_error "Unsupported Linux distribution"
    fi
    echo "User '$USERNAME' added to sudo group"
}

# Function to set custom hostname
set_custom_hostname() {
    read -p "Enter the new hostname: " NEW_HOSTNAME
    hostnamectl set-hostname "$NEW_HOSTNAME" || handle_error "Failed to set hostname"
    echo "Hostname set to $NEW_HOSTNAME"
}

# Function to configure SSH settings
configure_ssh() {
    read -p "Enter the custom SSH port: " SSH_PORT
    validate_input "Enter the custom SSH port: " SSH_PORT '^[0-9]+$'

    sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

    # SSH key generation
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

    local SSH_KEY_FILE="/home/$USERNAME/.ssh/id_$SSH_ALGO"

    # Check if the user wants to set a passphrase
    local SSH_PASSPHRASE

    read -p "Do you want to set a passphrase for the SSH key? [y/n]: " SET_PASSPHRASE

    if [[ $SET_PASSPHRASE =~ ^[Yy]$ ]]; then
        read -s -p "Enter passphrase for SSH key: " SSH_PASSPHRASE
        echo
        if [ -z "$SSH_PASSPHRASE" ]; then
            handle_error "Passphrase cannot be empty"
        fi
        read -s -p "Confirm passphrase: " CONFIRM_PASSPHRASE
        echo
        if [ "$SSH_PASSPHRASE" != "$CONFIRM_PASSPHRASE" ]; then
            handle_error "Passphrases do not match. Please try again."
        fi
    fi

    # Generate SSH keys for the user
    if [ -n "$SSH_KEY_BITS" ]; then
        sudo -u "$USERNAME" ssh-keygen -t "$SSH_ALGO" -b "$SSH_KEY_BITS" -f "$SSH_KEY_FILE" -N "$SSH_PASSPHRASE" || handle_error "SSH key generation failed"
    else
        sudo -u "$USERNAME" ssh-keygen -t "$SSH_ALGO" -f "$SSH_KEY_FILE" -N "$SSH_PASSPHRASE" || handle_error "SSH key generation failed"
    fi

    # Add the public key to authorized_keys
    cat "$SSH_KEY_FILE.pub" >> "/home/$USERNAME/.ssh/authorized_keys"

    # Adjust permissions
    chown -R "$USERNAME":"$USERNAME" "/home/$USERNAME/.ssh"
    chmod 700 "/home/$USERNAME/.ssh"
    chmod 600 "/home/$USERNAME/.ssh/authorized_keys"

    systemctl restart sshd
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

# Function to configure firewall
configure_firewall() {
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        # Debian/Ubuntu firewall configuration logic
        ufw default deny incoming
        ufw default allow outgoing

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

# Function to fetch the latest Prometheus release version from GitHub
get_latest_prometheus_version() {
    local latest_version=$(curl -s https://api.github.com/repos/prometheus/prometheus/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "$latest_version"
}

# Function to download Prometheus
download_prometheus() {
    local latest_version
    latest_version=$(get_latest_prometheus_version)
    local download_url="https://github.com/prometheus/prometheus/releases/download/$latest_version/prometheus-$latest_version.linux-amd64.tar.gz"

    # Download Prometheus
    wget "$download_url" -P /tmp || handle_error "Failed to download Prometheus"
}

# Function to extract Prometheus
extract_prometheus() {
    # Extract the Archive
    tar -xzf "/tmp/prometheus-$latest_version.linux-amd64.tar.gz" -C /tmp || handle_error "Failed to extract Prometheus archive"
}

# Function to configure Prometheus
configure_prometheus() {
    # Move Prometheus Files
    sudo mv "/tmp/prometheus-$latest_version.linux-amd64/prometheus" /usr/local/bin/ || handle_error "Failed to move Prometheus executable"
    sudo mv "/tmp/prometheus-$latest_version.linux-amd64/promtool" /usr/local/bin/ || handle_error "Failed to move Prometheus tool"

    # Create a Prometheus Configuration File
    sudo mkdir /etc/prometheus || handle_error "Failed to create Prometheus configuration directory"
    sudo touch /etc/prometheus/prometheus.yml || handle_error "Failed to create Prometheus configuration file"

    # Add Configuration to the File
    cat << EOF | sudo tee /etc/prometheus/prometheus.yml
global:
  scrape_interval:     15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
EOF
}

# Function to start Prometheus
start_prometheus() {
    # Create a Prometheus Systemd Service File
    cat << EOF | sudo tee /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/prometheus --web.console.templates=/etc/prometheus/consoles --web.console.libraries=/etc/prometheus/console_libraries
User=prometheus
Group=prometheus
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Create Necessary Directories
sudo mkdir /var/lib/prometheus || handle_error "Failed to create Prometheus data directory"

# Change Ownership of Prometheus Directory
sudo chown -R prometheus: /etc/prometheus /var/lib/prometheus || handle_error "Failed to change ownership of Prometheus directories"

    # Start and Enable Prometheus Service
    sudo systemctl daemon-reload || handle_error "Failed to reload systemd daemon"
    sudo systemctl start prometheus || handle_error "Failed to start Prometheus service"
    sudo systemctl enable prometheus || handle_error "Failed to enable Prometheus service"

    echo "Prometheus installed successfully."
}

# Function to install Prometheus
install_prometheus() {
    get_latest_prometheus_version
    download_prometheus
    extract_prometheus
    configure_prometheus
    start_prometheus
}

# Function to configure system logging
configure_logging() {
    systemctl enable rsyslog
    systemctl start rsyslog
}

# Function to configure fail2ban
configure_fail2ban() {
    # Configure fail2ban to only allow CZ IPs
    cat << EOF | sudo tee /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
banaction = iptables-multiport
banipregex = ^<HOST>$
EOF

    # Create a new jail file to specify CZ IPs
    cat << EOF | sudo tee /etc/fail2ban/action.d/iptables-geoip.conf
[Definition]
actionstart = <iptables> -N fail2ban-<name>
              <iptables> -A fail2ban-<name> -j RETURN
              <iptables> -I <chain> -p <protocol> -j fail2ban-<name>
actionstop = <iptables> -D <chain> -p <protocol> -j fail2ban-<name>
actioncheck = <iptables> -n -L <chain> | grep -q 'fail2ban-<name>[ \t]'
actionban = <iptables> -I fail2ban-<name> 1 -s <ip> -j DROP
actionunban = <iptables> -D fail2ban-<name> -s <ip> -j DROP
actionflush = <iptables> -F fail2ban-<name>
EOF

    # Download CZ IP ranges
    curl -sSL https://www.ipdeny.com/ipblocks/data/countries/cz.zone -o /etc/fail2ban/cz.zone || handle_error "Failed to download CZ IP ranges"

    # Create a new fail2ban jail to block IPs not from CZ
    cat << EOF | sudo tee /etc/fail2ban/jail.d/cz.conf
[cz]
enabled = true
filter = <filter>
action = iptables-geoip[name=czech, protocol=all]
logpath = /var/log/auth.log
EOF

    # Restart fail2ban
    systemctl restart fail2ban || handle_error "Failed to restart fail2ban"
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

# Main script execution
check_root
check_config
get_distribution
update_upgrade
install_packages
add_user
set_custom_hostname
configure_ssh
install_prometheus
configure_firewall
configure_fail2ban
configure_logging
configure_swap

echo "Setup completed successfully."

# Ask if the user wants to export SSH keys to GitHub
read -p "Do you want to export SSH keys to GitHub? (yes/no): " EXPORT_KEYS
if [ "$EXPORT_KEYS" == "yes" ]; then
    export_keys_to_github
fi

# Option to reboot the server
read -p "Setup completed successfully. Do you want to reboot the server now? (yes/no): " REBOOT_OPTION
if [ "$REBOOT_OPTION" == "yes" ]; then
    echo "Rebooting the server..."
    reboot
else
    echo "Reboot skipped. Please remember to reboot the server for changes to take effect."
fi
