# Blockchain-Encryption-Decryption-Script
For healthcare workers, informaticians, and researchers, this script encrypts and decrypts files with strong cryptography to protect ePHI. It secures data whether stored locally, emailed, or uploaded to the cloud, aligning with HIPAA standards for Encryption at Rest and Transmission Security.

#!/usr/bin/env python3
# ePHI Lockbox — Encrypt/Decrypt tool with blockchain-style audit logging
# Author: Jordan French (R. Jordan French)
# License: MIT

import os
import argparse
import base64
import hashlib
import logging
import json
from getpass import getpass
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# === Constants ===
KEYFILE = "ephilockbox.key"
LOGFILE = "logs/activity_log.txt"
BLOCKCHAIN_LOG = "logs/blockchain_log.jsonl"
SALT = b'ephi-salt-value'  # In production, generate a secure random salt per user/session

# === Setup ===
os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename=LOGFILE, level=logging.INFO, format='%(asctime)s %(message)s')

# === Key Management ===
def generate_key_from_password(password: str) -> bytes:
    """Derive a Fernet key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_fernet_key(password_mode: bool) -> Fernet:
    """Obtain Fernet key from file or password input."""
    if password_mode:
        password = getpass("Enter encryption password: ")
        key = generate_key_from_password(password)
    else:
        if not os.path.exists(KEYFILE):
            key = Fernet.generate_key()
            with open(KEYFILE, 'wb') as f:
                f.write(key)
        else:
            with open(KEYFILE, 'rb') as f:
                key = f.read()
    return Fernet(key)

# === Blockchain Logging ===
def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def compute_file_hash(file_path: str) -> str:
    """Return SHA-256 hash of file contents."""
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return "ERROR"

def get_last_log_hash() -> str:
    """Get hash of the last blockchain log entry."""
    if not os.path.exists(BLOCKCHAIN_LOG):
        return "0" * 64  # Genesis hash
    with open(BLOCKCHAIN_LOG, 'r') as f:
        lines = f.readlines()
        if not lines:
            return "0" * 64
        last_entry = json.loads(lines[-1])
        return last_entry["entry_hash"]

def log_blockchain_event(action: str, file_path: str):
    """Append a blockchain-style log entry."""
    timestamp = datetime.now().isoformat()
    file_hash = compute_file_hash(file_path)
    previous_hash = get_last_log_hash()

    entry = {
        "timestamp": timestamp,
        "action": action,
        "file": file_path,
        "file_hash": file_hash,
        "previous_hash": previous_hash
    }

    # Hash the entry (excluding the entry_hash itself)
    entry_json = json.dumps(entry, sort_keys=True)
    entry["entry_hash"] = sha256(entry_json)

    with open(BLOCKCHAIN_LOG, 'a') as f:
        f.write(json.dumps(entry) + '\n')

# === Encryption / Decryption ===
def encrypt_file(file_path: str, fernet: Fernet):
    """Encrypt a file and create a blockchain log entry."""
    output_path = file_path + '.enc'
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(encrypted)
        logging.info(f"Encrypted: {file_path} -> {output_path}")
        log_blockchain_event("ENCRYPTED", file_path)
        print(f"[+] Encrypted: {file_path}")
    except Exception as e:
        print(f"[!] Failed to encrypt {file_path}: {e}")

def decrypt_file(file_path: str, fernet: Fernet):
    """Decrypt a .enc file and create a blockchain log entry."""
    if not file_path.endswith('.enc'):
        print(f"[!] Skipping {file_path}: Not an .enc file")
        return
    output_path = file_path.replace('.enc', '')
    try:
        with open(file_path, 'rb') as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        logging.info(f"Decrypted: {file_path} -> {output_path}")
        log_blockchain_event("DECRYPTED", output_path)
        print(f"[+] Decrypted: {file_path}")
    except Exception as e:
        print(f"[!] Failed to decrypt {file_path}: {e}")

def process_directory(path: str, fernet: Fernet, mode: str):
    """Recursively encrypt or decrypt all files in a directory."""
    for root, _, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)
            if mode == 'encrypt' and not file.endswith('.enc'):
                encrypt_file(full_path, fernet)
            elif mode == 'decrypt' and file.endswith('.enc'):
                decrypt_file(full_path, fernet)

# === CLI Interface ===
def main():
    parser = argparse.ArgumentParser(description="ePHI Lockbox — Encrypt/Decrypt files with blockchain-style audit log")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode of operation")
    parser.add_argument("-f", "--file", help="Path to a single file")
    parser.add_argument("-d", "--directory", help="Path to a folder to process recursively")
    parser.add_argument("--password", action="store_true", help="Use password-derived encryption key instead of a stored key file")

    args = parser.parse_args()
    fernet = get_fernet_key(password_mode=args.password)

    if args.file:
        if args.mode == "encrypt":
            encrypt_file(args.file, fernet)
        else:
            decrypt_file(args.file, fernet)
    elif args.directory:
        process_directory(args.directory, fernet, mode=args.mode)
    else:
        parser.error("You must specify either --file or --directory.")

if __name__ == "__main__":
    main()
