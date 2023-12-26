import os
from colorama import Fore, init
import subprocess
import sys
from fernet_encryption import encrypt, decrypt, encrypt_folder, decrypt_folder, generate_key
import time

def clear_console():
    subprocess.call("cls" if os.name == "nt" else "clear", shell=True)

def main():
    print("""
          Which encryption method do you want to use?
          
          [1] AES x Fernet - Method
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
            password = input("Enter the password that should be used for encryption:\n")
            key = generate_key(password=password)
            encrypt(filename=path, key=key)
            print("[+] Finished encrypting")
        elif dec == True:
            password = input("Enter the password that should be used for decryption:\n")
            key = generate_key(password=password, load_existing_salt=True)
            decrypt(filename=path, key=key)
            print("[+] Finished decrypting")
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
