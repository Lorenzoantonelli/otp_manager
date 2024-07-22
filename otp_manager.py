#! /usr/bin/env python3

import os
import sys
import json
import base64
import time
import subprocess
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
import pyotp


class OTPManager:
    def __init__(self):
        self.base_dir = os.path.expanduser("~/.otp_manager")
        self.secrets_dir = os.path.join(self.base_dir, "secrets")
        self.salt_file = os.path.join(self.base_dir, "salt")
        self.hash_file = os.path.join(self.base_dir, "hash")
        self.session_file = os.path.join(self.base_dir, "session")
        self.ensure_dirs()
        self.salt = self.get_or_create_salt()
        self.key = None
        self.session_duration = 3600  # 1 hour

    def ensure_dirs(self):
        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs(self.secrets_dir, exist_ok=True)

    def get_or_create_salt(self):
        if os.path.exists(self.salt_file):
            with open(self.salt_file, "rb") as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, "wb") as f:
                f.write(salt)
            return salt

    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def get_or_create_hash(self, password):
        if os.path.exists(self.hash_file):
            with open(self.hash_file, "rb") as f:
                return f.read()
        else:
            hashed_password = self.derive_key(password)
            with open(self.hash_file, "wb") as f:
                f.write(hashed_password)
            return hashed_password

    def create_session(self):
        session_key = Fernet.generate_key()
        expiration_time = int(time.time()) + self.session_duration
        session_data = {"key": self.key.decode(), "expiration": expiration_time}
        f = Fernet(session_key)
        encrypted_session = session_key + f.encrypt(json.dumps(session_data).encode())
        with open(self.session_file, "wb") as file:
            file.write(encrypted_session)
        print(
            f"New session created. It will expire in {self.session_duration // 3600} hour(s)."
        )

    def load_session(self):
        if not os.path.exists(self.session_file):
            return False
        with open(self.session_file, "rb") as file:
            encrypted_session = file.read()
        try:
            session_key = encrypted_session[:44]
            f = Fernet(session_key)
            decrypted_session = json.loads(f.decrypt(encrypted_session[44:]))
            if decrypted_session["expiration"] > int(time.time()):
                self.key = decrypted_session["key"].encode()
                return True
        except:
            pass
        return False

    def unlock(self, password):
        stored_hash = self.get_or_create_hash(password)
        if stored_hash == self.derive_key(password):
            self.key = stored_hash
            self.create_session()
            return True
        else:
            print("Invalid password.")
            sys.exit(1)

    def lock(self):
        if os.path.exists(self.session_file):
            os.remove(self.session_file)
        self.key = None
        print("OTP Manager has been locked.")

    def encrypt_secret(self, secret):
        f = Fernet(self.key)
        return f.encrypt(secret.encode()).decode()

    def decrypt_secret(self, encrypted_secret):
        f = Fernet(self.key)
        return f.decrypt(encrypted_secret.encode()).decode()

    def add_secret(self, name, secret, digits=6, interval=30):
        encrypted_secret = self.encrypt_secret(secret)
        secret_data = {
            "name": name,
            "secret": encrypted_secret,
            "digits": digits,
            "interval": interval,
        }
        file_path = os.path.join(self.secrets_dir, f"{name}.json")
        with open(file_path, "w") as file:
            json.dump(secret_data, file)
        print(f"Secret '{name}' added successfully.")

    def update_secret(self, name, new_secret, digits=None, interval=None):
        file_path = os.path.join(self.secrets_dir, f"{name}.json")
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                secret_data = json.load(file)
            encrypted_secret = self.encrypt_secret(new_secret)
            secret_data["secret"] = encrypted_secret
            if digits:
                secret_data["digits"] = digits
            if interval:
                secret_data["interval"] = interval
            with open(file_path, "w") as file:
                json.dump(secret_data, file)
            print(f"Secret '{name}' updated successfully.")
        else:
            print(f"No secret found with name '{name}'.")

    def delete_secret(self, name):
        file_path = os.path.join(self.secrets_dir, f"{name}.json")
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Secret '{name}' deleted successfully.")
        else:
            print(f"No secret found with name '{name}'.")

    def list_secrets(self):
        secrets = [
            os.path.splitext(f)[0]
            for f in os.listdir(self.secrets_dir)
            if f.endswith(".json")
        ]
        secrets.sort(key=str.casefold)
        if secrets:
            for name in secrets:
                print(name)
        else:
            print("No secrets stored.")
            sys.exit(1)

    def generate_otp(self, name, copy_to_clipboard=False):
        file_path = os.path.join(self.secrets_dir, f"{name}.json")
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                secret_data = json.load(file)
            decrypted_secret = self.decrypt_secret(secret_data["secret"])
            totp = pyotp.TOTP(
                decrypted_secret,
                digits=secret_data["digits"],
                interval=secret_data["interval"],
            )
            otp = totp.now()
            print(f"OTP for '{name}': {otp}")
            if copy_to_clipboard:
                self.text_to_clipboard(otp)
            return otp
        else:
            print(f"No secret found with name '{name}'.")

    def text_to_clipboard(self, text):
        if sys.platform.startswith("linux"):
            if "WAYLAND_DISPLAY" in os.environ:
                try:
                    subprocess.run(["wl-copy"], input=text.encode(), check=True)
                except FileNotFoundError:
                    print("wl-copy not found, is it installed?", file=sys.stderr)
                    exit(0)
            elif "DISPLAY" in os.environ:
                try:
                    p = subprocess.Popen(["xsel", "-bi"], stdin=subprocess.PIPE)
                    p.communicate(input=text.encode())
                except FileNotFoundError:
                    print("xsel not found, is it installed?", file=sys.stderr)
                    exit(0)
        elif sys.platform.startswith("darwin"):
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        elif sys.platform.startswith("win"):
            try:
                import pyperclip

                pyperclip.copy(text)
            except ImportError:
                print("pyperclip not found, please install it", file=sys.stderr)
                exit(0)

    def import_aegis_json(self, json_file):
        try:
            with open(json_file, "r") as f:
                aegis_data = json.load(f)

            if "db" not in aegis_data or "entries" not in aegis_data["db"]:
                print("Invalid Aegis JSON format.")
                sys.exit(1)

            imported_count = 0
            for entry in aegis_data["db"]["entries"]:
                if entry["type"] != "totp":
                    continue

                issuer = entry["issuer"].strip() if entry["issuer"] else ""
                name = entry["name"].strip()

                if issuer.lower() == name.lower():
                    name = issuer or name
                elif issuer:
                    name = f"{issuer}_{name}"

                secret = entry["info"]["secret"]
                digits = entry["info"].get("digits", 6)
                period = entry["info"].get("period", 30)

                file_path = os.path.join(self.secrets_dir, f"{name}.json")
                if os.path.exists(file_path):
                    print(f"Secret '{name}' already exists. Skipping.")
                    continue

                self.add_secret(name, secret, digits, period)
                imported_count += 1

            print(
                f"Successfully imported {imported_count} TOTP secrets from Aegis backup."
            )
        except json.JSONDecodeError:
            print("Invalid JSON file.")
            sys.exit(1)
        except FileNotFoundError:
            print(f"File not found: {json_file}")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred while importing: {str(e)}")
            sys.exit(1)

    def rename_service(self, old_name, new_name):
        old_file_path = os.path.join(self.secrets_dir, f"{old_name}.json")
        new_file_path = os.path.join(self.secrets_dir, f"{new_name}.json")

        if not os.path.exists(old_file_path):
            print(f"No secret found with name '{old_name}'.")
            sys.exit(1)

        if os.path.exists(new_file_path):
            print(f"A secret with name '{new_name}' already exists.")
            sys.exit(1)

        try:
            with open(old_file_path, "r") as file:
                secret_data = json.load(file)

            secret_data["name"] = new_name

            with open(new_file_path, "w") as file:
                json.dump(secret_data, file)

            os.remove(old_file_path)

            print(f"Secret renamed from '{old_name}' to '{new_name}' successfully.")
        except Exception as e:
            print(f"An error occurred while renaming the secret: {str(e)}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="OTP Manager")
    parser.add_argument(
        "action",
        choices=[
            "unlock",
            "lock",
            "add",
            "update",
            "delete",
            "list",
            "generate",
            "import",
            "rename",
        ],
        help="Action to perform",
    )
    parser.add_argument(
        "name",
        nargs="?",
        help="Name of the secret, path to Aegis JSON file for import, or old name for rename",
    )
    parser.add_argument("new_name", nargs="?", help="New name for rename action")
    parser.add_argument("--secret", help="Secret value (for add and update actions)")
    parser.add_argument(
        "--digits", type=int, default=6, help="Number of digits for OTP (default: 6)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Time interval for OTP in seconds (default: 30)",
    )
    parser.add_argument(
        "--copy", action="store_true", help="Copy generated OTP to clipboard"
    )
    args = parser.parse_args()

    manager = OTPManager()

    if args.action == "lock":
        manager.lock()
        return

    if not manager.load_session():
        if args.action != "unlock":
            print("Session expired or not found. Please unlock the OTP manager.")
            sys.exit(1)
        password = getpass("Enter your master password: ")
        if not manager.unlock(password):
            print("Failed to unlock OTP manager.")
            sys.exit(1)
    elif args.action == "unlock":
        print("OTP manager is already unlocked.")
        return

    if args.action == "add":
        if args.name:
            secret = args.secret if args.secret else getpass("Enter the secret: ")
            manager.add_secret(args.name, secret, args.digits, args.interval)
        else:
            print("Name is required for add action.")
            sys.exit(1)
    elif args.action == "update":
        if args.name and args.secret:
            manager.update_secret(args.name, args.secret, args.digits, args.interval)
        else:
            print("Both name and secret are required for update action.")
            sys.exit(1)
    elif args.action == "delete":
        if args.name:
            manager.delete_secret(args.name)
        else:
            print("Name is required for delete action.")
            sys.exit(1)
    elif args.action == "list":
        manager.list_secrets()
    elif args.action == "generate":
        if args.name:
            manager.generate_otp(args.name, copy_to_clipboard=args.copy)
        else:
            print("Name is required for generate action.")
            sys.exit(1)
    elif args.action == "import":
        if args.name:
            manager.import_aegis_json(args.name)
        else:
            print("Path to Aegis JSON file is required for import action.")
            sys.exit(1)
    elif args.action == "rename":
        if args.name and args.new_name:
            manager.rename_service(args.name, args.new_name)
        else:
            print("Both old name and new name are required for rename action.")
            sys.exit(1)


if __name__ == "__main__":
    main()
