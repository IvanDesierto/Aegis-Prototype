import uuid, hashlib, base64, os
from cryptography.fernet import Fernet

def get_hardware_key(MAC):
    byte_key = str(MAC).encode()
    hash_digest = hashlib.sha256(byte_key).digest()
    return base64.urlsafe_b64encode(hash_digest)

def create_aegis_file():
    MAC = uuid.getnode()
    MAC_key = get_hardware_key(MAC)
    cipher = Fernet(MAC_key)

    file_name = input("Enter name of file: ").strip()
    if not file_name.endswith(".aegis"):
        file_name += ".aegis"

    secret_data = input("Enter data to lock: ")
    
    encrypted_data = cipher.encrypt(secret_data.encode())  

    header = b"AEGIS-V1:"
    extension = b".aegis"

    with open(file_name, "wb") as f:    
        f.write(header)
        f.write(encrypted_data)
        f.write(extension)

    print(f"\n Successfully created {file_name}")
    print("This file can now only be unlocked by your MAC")

if __name__ == "__main__":
    create_aegis_file()

    

    