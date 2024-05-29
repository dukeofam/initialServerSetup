#!/bin/bash

# Function to display colorful banners
display_banner() {
    local banner_text="$1"
    local color="$2"
    echo -e "\e[${color}m=========================================="
    echo -e "     $banner_text"
    echo -e "==========================================\e[0m"
}

# Function to check if the script is running as root
check_root() {
    display_banner "CHECKING FOR ROOT" "33"
    if [ "$EUID" -ne 0 ]; then
        echo -e "\e[31m\u2717\e[0m Please run as root"
        exit 1
    else
        echo -e "\e[32m\u2713\e[0m Root access granted"
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
    display_banner "CHECKING CONFIG FILE" "33"
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "\e[32m\u2713\e[0m Configuration file found"
        # Read configuration settings from the file
        source "$CONFIG_FILE"
    else
        echo -e "\e[31m\u2717\e[0m No config file found. Skipping configuration."
    fi
}

# Function to validate user inputs
validate_input() {
    local prompt="$1"
    local var_name="$2"
    local pattern="$3"

    while true; do
        read -p $'\e[1;34m'"$prompt"$'\e[0m' "$var_name"
        if [[ ${!var_name} =~ $pattern ]]; then
            break
        else
            echo -e "\e[1;31mInvalid input. Please try again.\e[0m"
        fi
    done
}

# Function to handle errors gracefully
handle_error() {
    local error_message="$1"
    echo -e "\e[31mError: $error_message\e[0m" >&2
    exit 1
}

# Function to determine the Linux distribution
get_distribution() {
    display_banner "CHECKING DISTRIBUTION" "33"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        echo -e "\e[32m\u2713\e[0m Detected Linux distribution: $DISTRO"
    elif [ -f /etc/centos-release ]; then
        DISTRO="centos"
        echo -e "\e[32m\u2713\e[0m Detected Linux distribution: $DISTRO"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        echo -e "\e[32m\u2713\e[0m Detected Linux distribution: $DISTRO"
    else
        echo -e "\e[31m\u2717\e[0m Unsupported Linux distribution"
        handle_error "Unsupported Linux distribution"
    fi
}

# Function to change the root password
root_password() {
    local PASSWORD

    display_banner "CHANGE ROOT PASSWORD" "33"

    echo -e "\e[93mThe password is not visible while being changed. Proceed carefully.\e[0m"

    while true; do
    echo
    read -s -p $'\e[1;34mEnter your new password: \e[0m' PASSWORD
    echo
    read -s -p $'\e[1;34mConfirm your new password: \e[0m' PASSWORD_CONFIRM
    echo

    if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
        echo $'\e[1;31mPasswords do not match. Please try again.\e[0m'
    else
        echo $'\e[1;32mChanging root password...\e[0m'
        echo "root:$PASSWORD" | chpasswd
        if [ $? -eq 0 ]; then
            echo $'\e[1;32mRoot password changed successfully.\e[0m'
            break
        else
            echo $'\e[1;31mFailed to change root password. Please try again.\e[0m'
        fi
    fi
done
}

# Function to update and upgrade the system
update_upgrade() {
    display_banner "UPDATE & UPGRADE" "34"

    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        apt update && apt upgrade -y && echo -e "\e[32mSystem updated and upgraded successfully.\e[0m" || handle_error "Failed to update and upgrade system"
        apt install -y unattended-upgrades && echo -e "\e[32mUnattended upgrades installed successfully.\e[0m" || handle_error "Failed to install unattended-upgrades"
        dpkg-reconfigure --priority=low unattended-upgrades && echo -e "\e[32mUnattended upgrades reconfigured successfully.\e[0m" || handle_error "Failed to reconfigure unattended-upgrades"
        apt autoremove -y && echo -e "\e[32mUnused packages removed successfully.\e[0m"
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        yum update -y && yum upgrade -y && echo -e "\e[32mSystem updated and upgraded successfully.\e[0m" || handle_error "Failed to update and upgrade system"
        yum install -y yum-cron && echo -e "\e[32mYum-cron installed successfully.\e[0m" || handle_error "Failed to install yum-cron"
        systemctl start yum-cron && echo -e "\e[32mYum-cron service started successfully.\e[0m" || handle_error "Failed to start yum-cron"
        systemctl enable yum-cron && echo -e "\e[32mYum-cron service enabled successfully.\e[0m" || handle_error "Failed to enable yum-cron"
    else
        handle_error "Unsupported Linux distribution"
    fi
}

# Function to install necessary packages
install_packages() {
    display_banner "INSTALL PACKAGES" "34"

    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        apt install -y tmux tor htop ufw fail2ban logrotate rsyslog certbot nginx && echo -e "\e[32mPackages installed successfully.\e[0m" || handle_error "Failed to install packages"
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        yum install -y tmux tor htop firewalld epel-release fail2ban logrotate rsyslog certbot nginx && echo -e "\e[32mPackages installed successfully.\e[0m" || handle_error "Failed to install packages"
    else
        handle_error "Unsupported Linux distribution"
    fi
}

USERNAME=""
SSH_KEY_FILE=""

# Function to add a user and add it to the sudo group
add_user() {
    display_banner "ADD USER" "33"

    validate_input "Enter the username to create: " USERNAME '^[a-z_][a-z0-9_-]*[$]?$'

    if id "$USERNAME" &>/dev/null; then
        echo -e "\e[33mUser '$USERNAME' already exists\e[0m"
    else
        useradd -m -s /bin/bash "$USERNAME" && echo -e "\e[32mUser '$USERNAME' created successfully\e[0m" || handle_error "Failed to create user"
    fi

    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]; then
        usermod -aG sudo "$USERNAME" && echo -e "\e[32mUser '$USERNAME' added to sudo group\e[0m" || handle_error "Failed to add user to sudo group"
    elif [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; then
        usermod -aG wheel "$USERNAME" && echo -e "\e[32mUser '$USERNAME' added to wheel group\e[0m" || handle_error "Failed to add user to wheel group"
    else
        handle_error "Unsupported Linux distribution"
    fi
}


# Function to set custom hostname
set_custom_hostname() {
    display_banner "SET HOSTNAME" "34"
    
    read -p $'\e[1;33m'"Enter the new hostname (leave blank for default): "$'\e[0m' NEW_HOSTNAME
    if [ -n "$NEW_HOSTNAME" ]; then
        hostnamectl set-hostname "$NEW_HOSTNAME" || handle_error "Failed to set hostname"
        echo -e "\e[1;32mHostname set to $NEW_HOSTNAME\e[0m"
    else
        echo -e "\e[1;33mNo change made to hostname\e[0m"
    fi
}

# Function to configure SSH settings
configure_ssh() {
    display_banner "SSH CONFIGURATION" "31"

    # Validate SSH port within the specified range
    local SSH_PORT_MIN=10001
    local SSH_PORT_MAX=65535
    while true; do
        read -p $'\e[1;34m'"Enter the custom SSH port ($SSH_PORT_MIN-$SSH_PORT_MAX): "$'\e[0m' SSH_PORT

        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
            echo -e "\e[31mInvalid input. Please enter a valid number.\e[0m"
            continue
        fi
        if (( SSH_PORT < SSH_PORT_MIN || SSH_PORT > SSH_PORT_MAX )); then
            echo -e "\e[31mInvalid port. Please enter a port within the range $SSH_PORT_MIN-$SSH_PORT_MAX.\e[0m"
        else
            echo -e "\e[32mSSH port set to $SSH_PORT\e[0m"
            break
        fi
    done

    sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

    # SSH key generation
    display_banner "SSH KEY GENERATION" "33"
    echo -e "\e[33mChoose the SSH encryption algorithm:\e[0m"
    echo -e "\e[34m1) RSA (4096 bits)\e[0m"
    echo -e "\e[34m2) ECDSA (521 bits)\e[0m"
    echo -e "\e[34m3) ED25519\e[0m"
    read -p $'\e[33mEnter the number corresponding to your choice: \e[0m' ALGO_CHOICE

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
            echo -e "\e[31mInvalid choice. Defaulting to ED25519.\e[0m"
            SSH_ALGO="ed25519"
            SSH_KEY_BITS=""
            ;;
    esac

    SSH_KEY_FILE="/home/$USERNAME/.ssh/id_$SSH_ALGO"
    echo -e "\e[32mSSH key generation completed successfully.\e[0m"

    # Check if the user wants to set a passphrase
    local SSH_PASSPHRASE

    read -p $'\e[33mDo you want to set a passphrase for the SSH key? [y/n]: \e[0m' SET_PASSPHRASE

    if [[ $SET_PASSPHRASE =~ ^[Yy]$ ]]; then
    read -s -p $'\e[33mEnter passphrase for SSH key: \e[0m' SSH_PASSPHRASE
    echo
    if [ -z "$SSH_PASSPHRASE" ]; then
        handle_error "Passphrase cannot be empty"
    fi
    read -s -p $'\e[33mConfirm passphrase: \e[0m' CONFIRM_PASSPHRASE
    echo
    if [ "$SSH_PASSPHRASE" != "$CONFIRM_PASSPHRASE" ]; then
        handle_error "Passphrases do not match. Please try again."
    else echo -e "\e[32mSSH passphrase set successfully.\e[0m"
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

# Restart SSH service for changes to take effect
if systemctl restart sshd; then
    echo -e "\e[32mThe keys have been generated and moved to the 'authorized_keys' folder. The SSH server has been restarted.\e[0m"
else
    handle_error "Failed to restart SSH service"
fi
}

# Function to export SSH keys to GitHub private repository
export_keys_to_github() {
    display_banner "EXPORT KEYS TO GITHUB" "29"
    read -p "$(tput setaf 3)Enter your private GitHub repository URL: $(tput sgr0)" GITHUB_REPO_URL
    read -p "$(tput setaf 3)Enter your GitHub API key: $(tput sgr0)" -s GITHUB_API_KEY
    echo
    read -p "$(tput setaf 3)Enter the temporary local directory to clone the repository [/tmp/ssh-keys-backup]: $(tput sgr0)" LOCAL_REPO_DIR
    LOCAL_REPO_DIR=${LOCAL_REPO_DIR:-/tmp/ssh-keys-backup}

    # Ensure the user's public/private key exists
    if [ ! -f "$SSH_KEY_FILE" ]; then
        echo "$(tput setaf 1)SSH keys for user '$USERNAME' not found.$(tput sgr0)"
        return 1
    fi

    # Extract username and repository path from the GitHub URL
    GITHUB_URL_NO_PROTOCOL=$(echo "$GITHUB_REPO_URL" | sed -e 's/^https:\/\///')
    GITHUB_USER_REPO=$(echo "$GITHUB_URL_NO_PROTOCOL" | sed -e 's/^.*@//')

    # Construct the authenticated URL
    AUTHENTICATED_URL="https://${GITHUB_API_KEY}@${GITHUB_USER_REPO}"

    # Clone the repository
    git clone "$AUTHENTICATED_URL" "$LOCAL_REPO_DIR" || handle_error "$(tput setaf 1)Failed to clone GitHub repository$(tput sgr0)"
    echo "$(tput setaf 2)Cloned GitHub repository successfully.$(tput sgr0)"

    # Copy SSH keys to the repository directory
    cp "$SSH_KEY_FILE" "$LOCAL_REPO_DIR/" || handle_error "$(tput setaf 1)Failed to copy SSH private key$(tput sgr0)"
    cp "$SSH_KEY_FILE.pub" "$LOCAL_REPO_DIR/" || handle_error "$(tput setaf 1)Failed to copy SSH public key$(tput sgr0)"
    echo "$(tput setaf 2)Copied SSH keys to the repository directory.$(tput sgr0)"

    # Commit and push the changes
    cd "$LOCAL_REPO_DIR" || handle_error "$(tput setaf 1)Failed to change directory to $LOCAL_REPO_DIR$(tput sgr0)"
    git add id_$SSH_ALGO id_$SSH_ALGO.pub
    git commit -m "Add new SSH keys for $USERNAME" || handle_error "$(tput setaf 1)Failed to commit changes$(tput sgr0)"
    git push origin main || handle_error "$(tput setaf 1)Failed to push changes to GitHub$(tput sgr0)"
    echo "$(tput setaf 2)Committed and pushed the changes to GitHub successfully.$(tput sgr0)"

    # Clean up
    rm -rf "$LOCAL_REPO_DIR" || handle_error "$(tput setaf 1)Failed to remove temporary directory$(tput sgr0)"
    echo "$(tput setaf 2)Cleaned up temporary directory.$(tput sgr0)"
}

# Helper function to validate and add a port rule
add_port_rule() {
    local distro=$1
    local action=$2
    local ip_address=$3
    local port=$4

    case $distro in
        debian|ubuntu)
            if [ -n "$ip_address" ]; then
                ufw $action from "$ip_address" to any port "$port"
            else
                ufw $action "$port"
            fi
            ;;
        centos|rhel)
            if [ -n "$ip_address" ]; then
                firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip_address' $action port port='$port' protocol='tcp'"
            else
                firewall-cmd --permanent --$action-port="$port"/tcp
            fi
            ;;
        *)
            echo "Unsupported Linux distribution"
            exit 1
            ;;
    esac
}

# Function to configure firewall
configure_firewall() {
    display_banner "FIREWALL CONFIGURATION" "31"
    echo "$(tput setaf 3)Please enter any ports you'd like to open through the firewall. Press Enter without input to finish.$(tput sgr0)"

    # Validate port within the specified range
    local PORT_MIN=1
    local PORT_MAX=65535

    while true; do
        read -p "$(tput setaf 3)Enter the custom port for firewall rules ($PORT_MIN-$PORT_MAX): $(tput sgr0)" port
        # Check if the input is empty (user pressed Enter without input)
        if [[ -z "$port" ]]; then
            break
        fi

        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            echo "$(tput setaf 1)Invalid input. Please enter a valid number.$(tput sgr0)"
            continue
        fi

        if (( port < PORT_MIN || port > PORT_MAX )); then
            echo "$(tput setaf 1)Invalid port. Please enter a port within the range $PORT_MIN-$PORT_MAX.$(tput sgr0)"
            continue
        fi

        # Validate IP address format and range
        read -p "$(tput setaf 3)Enter IP address to allow access for port $port (format: x.x.x.x, each octet between 0-255, leave empty to allow all IPs): $(tput sgr0)" ip_address
        if [[ -z "$ip_address" ]]; then
            # If IP address is empty, allow all IPs
            ip_address="0.0.0.0/0"
        else
            while true; do
                if [[ "$ip_address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                    valid_ip=true
                    for octet in $(echo "$ip_address" | tr '.' ' '); do
                        if (( octet < 0 || octet > 255 )); then
                            valid_ip=false
                            break
                        fi
                    done
                    if $valid_ip; then
                        break
                    else
                        echo "$(tput setaf 1)Invalid IP address format or range. Each octet should be between 0 and 255.$(tput sgr0)"
                    fi
                else
                    echo "$(tput setaf 1)Invalid IP address format. Please enter a valid IPv4 address.$(tput sgr0)"
                fi
                read -p "$(tput setaf 3)Enter IP address to allow access for port $port (format: x.x.x.x, each octet between 0-255, leave empty to allow all IPs): $(tput sgr0)" ip_address
            done
        fi

        # Add the port rule
        add_port_rule $DISTRO allow "$ip_address" $port
    done

    case $DISTRO in
        debian|ubuntu)
            ufw default deny incoming
            ufw default allow outgoing
            ufw --force enable
            ;;
        centos|rhel)
            systemctl start firewalld
            systemctl enable firewalld
            firewall-cmd --set-default-zone=drop
            firewall-cmd --permanent --zone=drop --add-interface=eth0
            firewall-cmd --reload
            ;;
        *)
            echo "Unsupported Linux distribution"
            exit 1
            ;;
    esac
}

latest_version=""
download_url=""

# Function to fetch the latest Prometheus release version from GitHub
get_latest_prometheus_version() {
    display_banner "PROMETHEUS CONFIGURATION" "31"

    latest_version=$(curl -s https://api.github.com/repos/prometheus/prometheus/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    # Remove the leading "v" if it exists
    latest_version=${latest_version#v}
}

# Function to download Prometheus
download_prometheus() {
    download_url="https://github.com/prometheus/prometheus/releases/download/v$latest_version/prometheus-$latest_version.linux-amd64.tar.gz"
    echo "Downloading Prometheus version $latest_version from $download_url"
    wget "$download_url" -P /tmp/
}

# Function to extract Prometheus
extract_prometheus() {
    # Extract the Archive
   tar -xzf /tmp/prometheus-$latest_version.linux-amd64.tar.gz -C /tmp/ || handle_error "Failed to extract Prometheus archive"

}

# Function to configure Prometheus
configure_prometheus() {
    # Move Prometheus Files
    if [ ! -f "/usr/local/bin/prometheus" ]; then
        sudo mv "/tmp/prometheus-$latest_version.linux-amd64/prometheus" /usr/local/bin/ || handle_error "Failed to move Prometheus executable"
    else
        echo "Prometheus executable already exists. Skipping move."
    fi

    if [ ! -f "/usr/local/bin/promtool" ]; then
        sudo mv "/tmp/prometheus-$latest_version.linux-amd64/promtool" /usr/local/bin/ || handle_error "Failed to move Prometheus tool"
    else
        echo "Prometheus tool already exists. Skipping move."
    fi

    # Create a Prometheus Configuration File
    if [ ! -d "/etc/prometheus" ]; then
        sudo mkdir /etc/prometheus || handle_error "Failed to create Prometheus configuration directory"
    else
        echo "Prometheus configuration directory already exists. Skipping creation."
    fi

    if [ ! -f "/etc/prometheus/prometheus.yml" ]; then
        sudo touch /etc/prometheus/prometheus.yml || handle_error "Failed to create Prometheus configuration file"
    else
        echo "Prometheus configuration file already exists. Skipping creation."
    fi

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

# Function to add technical user Prometheus
add_prometheus_user() {
    useradd -m -s /bin/bash prometheus && echo "$(tput setaf 2)Prometheus user added successfully.$(tput sgr0)"
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
    if [ ! -d "/var/lib/prometheus" ]; then
        sudo mkdir /var/lib/prometheus && echo "$(tput setaf 2)Prometheus data directory created successfully.$(tput sgr0)" || handle_error "Failed to create Prometheus data directory"
    else
        echo "Prometheus data directory already exists. Skipping creation."
    fi

    # Change Ownership of Prometheus Directory
    sudo chown -R prometheus: /etc/prometheus /var/lib/prometheus && echo "$(tput setaf 2)Changed ownership of Prometheus directories successfully.$(tput sgr0)" || handle_error "Failed to change ownership of Prometheus directories"

    # Start and Enable Prometheus Service
    sudo systemctl daemon-reload && echo "$(tput setaf 2)Reloaded systemd daemon.$(tput sgr0)" || handle_error "Failed to reload systemd daemon"
    sudo systemctl start prometheus && echo "$(tput setaf 2)Prometheus service started successfully.$(tput sgr0)" || handle_error "Failed to start Prometheus service"
    sudo systemctl enable prometheus && echo "$(tput setaf 2)Prometheus service enabled successfully.$(tput sgr0)" || handle_error "Failed to enable Prometheus service"

echo "$(tput setaf 2)Prometheus installed successfully.$(tput sgr0)"
}

# Function to install Prometheus
install_prometheus() {
    get_latest_prometheus_version
    download_prometheus
    extract_prometheus
    add_prometheus_user
    configure_prometheus
    start_prometheus
}

# Function to configure system logging
configure_logging() {
    display_banner "CONFIGURING LOGGING" "33"
    systemctl enable rsyslog && echo "$(tput setaf 2)rsyslog enabled successfully.$(tput sgr0)"
    systemctl start rsyslog && echo "$(tput setaf 2)rsyslog started successfully.$(tput sgr0)"
}

# Function to configure fail2ban
configure_fail2ban() {
    display_banner "CONFIGURING FAIL2BAN" "33"
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
    curl -sSL https://www.ipdeny.com/ipblocks/data/countries/cz.zone -o /etc/fail2ban/cz.zone && echo "$(tput setaf 2)Downloaded CZ IP ranges successfully.$(tput sgr0)" || handle_error "Failed to download CZ IP ranges"

    # Create a new fail2ban jail to block IPs not from CZ
    cat << EOF | sudo tee /etc/fail2ban/jail.d/cz.conf
[cz]
enabled = true
filter = <filter>
action = iptables-geoip[name=czech, protocol=all]
logpath = /var/log/auth.log
EOF

    # Restart fail2ban
    systemctl restart fail2ban && echo "$(tput setaf 2)fail2ban restarted successfully.$(tput sgr0)" || handle_error "Failed to restart fail2ban"
}

# Function to configure swap space
configure_swap() {
    display_banner "SWAP SPACE CONFIG" "31"
    read -p "Enter the swapfile size (e.g., 2G): " SWAP_SIZE
    fallocate -l "$SWAP_SIZE" /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
    echo "$(tput setaf 2)Swap space configured successfully.$(tput sgr0)"
}

# Main script execution
check_root
read_config
get_distribution
update_upgrade
install_packages
root_password
add_user
set_custom_hostname
configure_ssh
export_keys_to_github
install_prometheus
configure_firewall
configure_fail2ban
configure_logging
configure_swap

echo "$(tput setaf 2)Setup completed successfully.$(tput sgr0)"

# Option to reboot the server
display_banner "SERVER REBOOT" "30"
read -p $'\e[1;32mSetup completed successfully. Do you want to reboot the server now? (yes/no): \e[0m' REBOOT_OPTION
if [ "$REBOOT_OPTION" == "yes" ]; then
    echo -e "\e[1;33mRebooting the server...\e[0m"
    reboot
else
    echo -e "\e[1;33mReboot skipped. Please remember to reboot the server for changes to take effect.\e[0m"
fi
