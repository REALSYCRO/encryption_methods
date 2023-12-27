from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from colorama import Fore, init
import os
import pathlib
import argparse

init(convert=True)

PRV_KEY_FILE = "private_key.pem"
PUB_KEY_FILE = "public_key.pem"

def generate_rsa_key_pair():
    if os.path.exists(PRV_KEY_FILE):
        os.remove(PRV_KEY_FILE)
    if os.path.exists(PUB_KEY_FILE):
        os.remove(PUB_KEY_FILE)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    with open(PRV_KEY_FILE, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    public_key = private_key.public_key()
    with open(PUB_KEY_FILE, "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1
            )
        )
    return private_key, public_key

def load_private_key():
    try:
        with open(PRV_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None  
            )
        return private_key
    except FileNotFoundError:
        print(f"Private key file '{PRV_KEY_FILE}' not found.")
        return None


def rsa_encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def rsa_encrypt_file(filename, public_key):
    with open(filename, "rb") as file:
        file_data = file.read()
    
    encrypted_data = rsa_encrypt(file_data, public_key)
    
    with open(filename, "wb") as file:
        file.write(encrypted_data)
        print(f"{Fore.GREEN}[+]{Fore.RESET} File encrypted")

def rsa_decrypt_file(filename, private_key):
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    
    decrypted_data = rsa_decrypt(encrypted_data, private_key)
    
    with open(filename, "wb") as file:
        file.write(decrypted_data)
        print(f"{Fore.GREEN}[+]{Fore.RESET} File decrypted")

def rsa_encrypt_folder(foldername, public_key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            rsa_encrypt_file(str(child), public_key)
            print(f"{Fore.GREEN}[+] Encrypted{Fore.RESET}")
        elif child.is_dir():
            rsa_encrypt_folder(str(child), public_key)

def rsa_decrypt_folder(foldername, private_key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Decrypting {child}")
            rsa_decrypt_file(str(child), private_key)
        elif child.is_dir():
            rsa_decrypt_folder(str(child), private_key)

def rsa_encryption(args):
    private_key, public_key = generate_rsa_key_pair()

    if args.encrypt:
        if os.path.exists(args.path):
            if os.path.isfile(args.path):
                rsa_encrypt_file(args.path, public_key)
            elif os.path.isdir(args.path):
                rsa_encrypt_folder(args.path, public_key)
            else:
                print("Invalid path or file does not exist.")
        else:
            print("Please provide a valid path.")
    elif args.decrypt:
        if os.path.exists(args.path):
            if os.path.isfile(args.path) and args.path.endswith(".encrypted"):
                rsa_decrypt_file(args.path, private_key)
            elif os.path.isdir(args.path):
                rsa_decrypt_folder(args.path, private_key)
            else:
                print("Invalid path or file is not encrypted.")
        else:
            print("Please provide a valid path.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RSA File Encryption/Decryption")
    parser.add_argument("path", help="Path to encrypt/decrypt, can be a file or an entire folder")
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Encrypt the file/folder")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Decrypt the file/folder")
    args = parser.parse_args()
    rsa_encryption(args)
