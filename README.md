# RANS 🔒

RANS is a command-line tool designed to securely encrypt and decrypt files and directories using AES-GCM encryption. This project is built with Python and provides a simple yet powerful way to protect your sensitive data.

## Features ✨

* **AES-GCM Encryption**: Encrypt and decrypt files using the AES-GCM (Authenticated Encryption with Associated Data) mode, providing both confidentiality and integrity.
* **Key and Nonce Generation**: Generates a secure random key and nonce for encryption, with options to save and load keys from files.
* **Directory Encryption/Decryption**: Encrypt or decrypt all files in a specified directory with a single command.
* **System Info Collection**: Collects detailed system information (e.g., OS, CPU, RAM, IP addresses, active connections, running processes) and sends it to a Discord webhook (if configured).
* **Cross-Platform**: Works on Windows, Linux, and macOS.

## Table of Contents 📑

* [Installation](#installation)
* [Usage](#usage)
* [Features](#features)
* [System Info Collected](#system-info-collected)
* [Security Notice](#security-notice)
* [Contributing](#contributing)
* [License](#license)

## Installation ⚙️

1. **Clone this repository**:

   ```bash
   git clone https://github.com/Gerijacki/rans
   cd rans
   ```

2. **Install required dependencies**:
   Make sure you have Python 3.x installed. Then, install the required libraries:

   ```bash
   pip install -r requirements.txt
   ```

## Usage 🛠️

### 1. Encrypt Files or Folders 🔒

To encrypt files in a folder, simply run the following command:

```bash
python src/main.py
```

* Enter the folder path containing the files you want to encrypt.
* Optionally, provide a Discord Webhook URL to send system information (e.g., IP address, CPU info) after encryption.

### 2. Decrypt Files or Folders 🔓

To decrypt encrypted files, use the following command:

```bash
python src/main.py
```

* Enter the folder path containing the encrypted files.
* Provide the path to the key file (`key.bin` or other) to decrypt the files.

### 3. Key and System Info Collection

The tool collects the following system information when generating or loading keys:

* Username
* Hostname
* Operating System and Version
* Architecture
* Processor details
* CPU cores
* RAM usage (total and percentage)
* Local and public IP addresses
* Active network connections
* Running processes
* Disk usage
* Firewall status

This information is saved as `system_info.json` and can be sent to a Discord webhook if configured.

## Features 🔑

* **Key and Nonce Generation**: Automatically generates a secure 256-bit key and nonce for AES-GCM encryption. The key is stored in `key.bin` for future decryption.
* **System Info Reporting**: Sends system information to a configured Discord webhook for auditing or monitoring purposes.
* **Folder-wide Encryption**: Encrypt or decrypt all files in a specified directory, recursively handling all files.
* **Real-Time Feedback**: Provides real-time feedback on encryption/decryption progress.
* **Compatibility**: Works across all major operating systems (Windows, macOS, Linux).

## System Info Collected 🖥️

* **OS**: Information about the operating system, version, and architecture.
* **CPU**: Number of cores and the processor type.
* **RAM**: Total RAM and memory usage percentage.
* **Disk Usage**: Current disk space usage.
* **IP Addresses**: Local and public IP addresses.
* **Active Network Connections**: List of active TCP/UDP connections.
* **Processes**: List of running processes with their PID, name, and user.
* **Firewall Status**: Checks the status of the system firewall (Linux).

## Security Notice ⚠️

* **Sensitive Information**: The system information and key are transmitted via Discord webhook if configured. Ensure that the webhook URL is kept private to prevent unauthorized access.
* **Encryption Key**: The encryption key should be stored securely. Loss of the key means loss of access to encrypted files.
* **Firewall and Security Configurations**: The firewall status is checked (on Linux systems) to assess system security.

## Contributing 🤝

1. **Fork the repository**:
   Click the "Fork" button at the top-right corner of the repository page.

2. **Create a branch**:
   Create a new branch for your changes.

   ```bash
   git checkout -b my-feature
   ```

3. **Commit your changes**:
   Add and commit your changes.

   ```bash
   git add .
   git commit -m "Added new feature"
   ```

4. **Push to your fork**:

   ```bash
   git push origin my-feature
   ```

5. **Create a pull request**:
   Submit your pull request to the main repository.

We welcome contributions! Please make sure to write tests for any new features or fixes.

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
