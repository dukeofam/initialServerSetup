# Bash Server Setup Script

This script automates the setup process for a Linux server, including system updates, package installations, user management, firewall configuration, and more.

## Prerequisites

- This script is designed for Linux servers.
- Root access is required to run this script.
- Ensure internet connectivity to download necessary packages.

## Usage

1. Clone the repository or download the script.
2. Make the script executable: `chmod +x server_setup.sh`
3. Run the script as root: `sudo ./server_setup.sh`
4. Follow the prompts to configure your server.

## Features

- **Root Check:** Ensures the script is run as root.
- **Configuration File:** Allows reading configuration settings from a file.
- **Distribution Detection:** Detects the Linux distribution.
- **Update & Upgrade:** Updates and upgrades the system.
- **Package Installation:** Installs necessary packages.
- **User Management:** Adds a new user and adds it to the sudo/wheel group.
- **Hostname Configuration:** Allows setting a custom hostname.
- **SSH Configuration:** Configures SSH settings and generates SSH keys.
- **Firewall Configuration:** Configures firewall rules.
- **Prometheus Installation:** Downloads, installs, and configures Prometheus monitoring tool.
- **Fail2ban Configuration:** Configures Fail2ban for enhanced security.
- **Logging Configuration:** Configures system logging.
- **Swap Space Configuration:** Creates and configures swap space.

## Contributors

- [Kr0now1](https://github.com/dukeofam)

## License

This project is licensed under the [MIT License](LICENSE).
