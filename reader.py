import uuid, sys, hashlib, base64, os
from cryptography.fernet import Fernet, InvalidToken

def get_hardware_key(MAC):
    byte_key = str(MAC).encode()
    hash_digest = hashlib.sha256(byte_key).digest()
    return base64.urlsafe_b64encode(hash_digest)

def self_destruct(file_name):
    print("Unauthorized user detected. Commencing Data Shredding \n")
    try:
        with open(file_name, "wb") as f:
            f.write(os.random(1024))

        os.remove(file_name)
        print("File has been removed.")
    except Exception as e:
        print("Failed to destroy file")
    
    sys.exit
        
def main():
    file_name = input("Enter file name: ")

    if not os.path.exists(file_name):
        print("Error not found")
        return
    
    with open(file_name, "rb") as f:
        full_content = f.read()

    header = b"SENTINEL-V1:"
    if not full_content.startswith(header):
        print("Error: invalid file format")
        return
    
    encrypted_payload = full_content[len(header):]
    
    current_MAC = uuid.getnode()
    key = get_hardware_key(current_MAC)
    cipher = Fernet(key)

    try:
    
        decrypted_bytes = cipher.decrypt(encrypted_payload)
      
        print(f"\n--- ACCESS GRANTED ---")
        print(f"DATA: {decrypted_bytes.decode()}")
        input("\nPress Enter to close the vault.")
    
    except InvalidToken:
       
        self_destruct(file_name)

if __name__ == "__main__":
    main()
    