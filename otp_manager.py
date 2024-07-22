import os
import sys
import json
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyotp
from crypto_utils import derive_key, encrypt_secret, decrypt_secret


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

    def get_or_create_hash(self, password):
        if os.path.exists(self.hash_file):
            with open(self.hash_file, "rb") as f:
                return f.read()
        else:
            hashed_password = derive_key(password, self.salt)
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
        if stored_hash == derive_key(password, self.salt):
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

    def add_secret(self, name, secret, digits=6, interval=30):
        encrypted_secret = encrypt_secret(secret, self.key)
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
            encrypted_secret = encrypt_secret(new_secret, self.key)
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

    def list_secrets(self, return_list=False):
        secrets = [
            os.path.splitext(f)[0]
            for f in os.listdir(self.secrets_dir)
            if f.endswith(".json")
        ]
        secrets.sort(key=str.casefold)
        if return_list:
            return secrets
        if secrets:
            for name in secrets:
                print(name)
        else:
            print("No secrets stored.")
        return None

    def generate_otp(self, name, copy_to_clipboard=False):
        file_path = os.path.join(self.secrets_dir, f"{name}.json")
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                secret_data = json.load(file)
            decrypted_secret = decrypt_secret(secret_data["secret"], self.key)
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
