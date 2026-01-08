import uuid, sys, hashlib, base64, os
from cryptography.fernet import Fernet, InvalidToken

def get_hardware_key(MAC):
    byte_key = str(MAC).encode()
    hash_digest = hashlib.sha256(byte_key).digest()
    return base64.urlsafe_b64encode(hash_digest)

def get_common_file_locations():
    home = os.path.expanduser("~")

    common_locations = [
        os.path.join(home, "Documents"),
        os.path.join(home, "Desktop"),
        os.path.join(home, "Downloads"),
        os.getcwd()
    ]

    found_files = []

    print("\nScanning common file locations for Aegis files")

    for location in common_locations:
        if os.path.exists(location):
            for root, dirs, files in os.walk(location):
                for file in files:
                    if file.endswith(".aegis"):
                        full_path = os.path.join(root, file)
                        found_files.append(full_path)
    
    return found_files


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

    aegis_files = get_common_file_locations()
    if not aegis_files:
        print("No aegis files were found in your device.")
        print("Move Aegis files into either Documents, Desktop, or Downloads")

    print("\n" + "="*40)
    print("     AEGIS FILE EXPLORER     ")
    print("="*40)
    print("")

    for i, path in enumerate(aegis_files):
        print(f"[{i}] {os.path.basename(path)} \nLocation: {path}\n" )
    print("="*50)

    try:
        choice = int(input("Enter number of Aegis file to open: "))
        open_file = aegis_files[choice]

    except Exception as e:
        print("Invalid selection")
        return

    with open(open_file, "rb") as f:
        full_content = f.read()

    header = b"AEGIS-V1:"
    extension = b".aegis"

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
        print(f"CONTENTS: {decrypted_bytes.decode()}")
        input("\nPress Enter to close the vault.")
    
    except InvalidToken:
       
        self_destruct(open_file)

if __name__ == "__main__":
    main()
    