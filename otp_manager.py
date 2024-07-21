#! /usr/bin/env python3

import os
import sys
import json
import base64
import time
import sys
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
            return False

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
            f.split(".")[0] for f in os.listdir(self.secrets_dir) if f.endswith(".json")
        ]
        secrets.sort()
        if secrets:
            for name in secrets:
                print(name)
        else:
            print("No secrets stored.")
            sys.exit(1)

    def generate_otp(self, name):
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
            return otp
        else:
            print(f"No secret found with name '{name}'.")


def main():
    parser = argparse.ArgumentParser(description="OTP Manager")
    parser.add_argument(
        "action",
        choices=["unlock", "lock", "add", "update", "delete", "list", "generate"],
        help="Action to perform",
    )
    parser.add_argument("name", nargs="?", help="Name of the secret")
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
    args = parser.parse_args()

    manager = OTPManager()

    if args.action == "lock":
        manager.lock()
        return

    if not manager.load_session():
        if args.action != "unlock":
            print("Session expired or not found. Please unlock the OTP manager.")
            return
        password = getpass("Enter your master password: ")
        if not manager.unlock(password):
            print("Failed to unlock OTP manager.")
            return
    elif args.action == "unlock":
        print("OTP manager is already unlocked.")
        return

    if args.action == "add":
        if args.name:
            secret = args.secret if args.secret else getpass("Enter the secret: ")
            manager.add_secret(args.name, secret, args.digits, args.interval)
        else:
            print("Name is required for add action.")
    elif args.action == "update":
        if args.name and args.secret:
            manager.update_secret(args.name, args.secret, args.digits, args.interval)
        else:
            print("Both name and secret are required for update action.")
    elif args.action == "delete":
        if args.name:
            manager.delete_secret(args.name)
        else:
            print("Name is required for delete action.")
    elif args.action == "list":
        manager.list_secrets()
    elif args.action == "generate":
        if args.name:
            manager.generate_otp(args.name)
        else:
            print("Name is required for generate action.")


if __name__ == "__main__":
    main()
