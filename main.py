import os
from colorama import Fore, init
import subprocess
import sys
from rsa_encryption import generate_rsa_key_pair, rsa_encrypt, rsa_decrypt, rsa_decrypt_folder, rsa_encrypt_folder, rsa_encrypt_file, rsa_decrypt_file, load_private_key
from fernet_encryption import encrypt, decrypt, encrypt_folder, decrypt_folder, generate_key
import time
import getpass


def clear_console():
    subprocess.call("cls" if os.name == "nt" else "clear", shell=True)

def main():
    print("""
Which encryption method do you want to use?
          
    [1] AES x Fernet - Method
    [2] RSA - Method
    [0] Exit\n
          """)
    
    choice = input("Please select your choice:\n")

    if "1" == choice:
        clear_console()
        enc = False
        dec = False
        encryption_or_decryption = input("Do you want to encrypt or decrypt? 1 for encrypt and 2 for decrypt: ")
        if encryption_or_decryption == "1":
            enc = True
        elif encryption_or_decryption == "2":
            dec = True
        path = input("Enter the path to the file or folder where the files are located: ")

        if enc == True:
            password = getpass.getpass("Enter the password that should be used for encryption:\n")
            key = generate_key(password=password)
            encrypt(filename=path, key=key)
            print("[+] Finished encrypting")
        elif dec == True:
            password = getpass.getpass("Enter the password that should be used for decryption:\n")
            key = generate_key(password=password, load_existing_salt=True)
            decrypt(filename=path, key=key)
            print("[+] Finished decrypting")
        else:
            print("[-] Error | You will be thrown back to the menu")
            time.sleep(1.1)
            clear_console()
            main()

    elif "2" == choice:
        clear_console()
        enc = False
        dec = False
        encryption_or_decryption = input("Do you want to encrypt or decrypt? 1 for encrypt and 2 for decrypt: ")
        if encryption_or_decryption == "1":
            enc = True
        elif encryption_or_decryption == "2":
            dec = True
        path = input("Enter the path to the file or folder where the files are located: ")
        if enc == True:
            if os.path.exists(path):
                if os.path.isfile(path):
                    _, public_key = generate_rsa_key_pair()
                    rsa_encrypt_file(filename=path, public_key=public_key)
                    print("[+] Finished")
                elif os.path.isdir(path):
                    _, public_key = generate_rsa_key_pair()
                    rsa_encrypt_folder(foldername=path, public_key=public_key)
                    print("[+] Finished")
                else:
                    print("[-] Error, maybe wrong path?")
            else:
                print("[-] Error, the path doesn't exist")
        elif dec == True:
            try:
                private_key = load_private_key()
                if os.path.exists(path):
                    if os.path.isfile(path):
                        rsa_decrypt_file(filename=path, private_key=private_key)
                        print("[+] Finished file decryption")
                    elif os.path.isdir(path):
                        rsa_decrypt_folder(foldername=path, private_key=private_key)
                        print("[+] Finished")
                    else:
                        print("[-] Error, maybe the wrong path?")
            except Exception as e:
                print(e)
        else:
            print("[-] Error | You will be thrown back to the menu")
            time.sleep(1.1)
            clear_console()
            main()


    elif "0" == choice:
        clear_console()
        print("Shutting down...")
        sys.exit()

    else:
        clear_console()
        print("[-] Invalid Input, going back to menu in 3 seconds...")
        time.sleep(3.0)
        main()

main()
