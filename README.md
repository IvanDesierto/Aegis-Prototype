# 🛡️ Aegis Security Suite
**Hardware-Bound Cryptographic Vault & Anti-Forensic Explorer**

Aegis is a two-part security ecosystem designed to tether sensitive data to specific hardware. Using a proprietary `.aegis` file format, it ensures that data created on one machine remains physically inaccessible on any other, featuring an active "Shred-on-Fail" mechanism.

---

## 🚀 The Core Ecosystem

| Component | Role | Description |
| :--- | :--- | :--- |
| **Aegis Forge** | Creator | Generates hardware-locked encrypted assets. |
| **Aegis Explorer** | Viewer | Scans the system, identifies assets, and enforces hardware validation. |

---

## ✨ Key Features

* **Hardware-Bound Encryption:** Keys are derived from the physical MAC address of the host machine using SHA-256 hashing.
* **Proprietary Container:** Files are wrapped in a custom binary format with unique `AEGIS-V1` headers.
* **Active Anti-Forensics:** Unauthorized access attempts trigger a secure wipe (2KB random noise overwrite) followed by file deletion.
* **Recursive Discovery:** The Explorer automatically scours `Documents`, `Desktop`, and `Downloads` for encrypted assets.

---

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/aegis-suite.git](https://github.com/yourusername/aegis-suite.git)


## Usage Guide
1. **Forging an Asset**
Run creator.py. Enter your secret data and a filename. The Forge will generate a .aegis file locked specifically to your computer's network identity.

2. **Accessing the Vault**
Run reader.py. The system will automatically list all compatible assets found in common user folders. Select the asset number to attempt decryption.

**[!CAUTION] WARNING:** Attempting to open an Aegis file on unauthorized hardware will result in the permanent destruction of the file. Do not move encrypted assets to other machines unless the recipient hardware is pre-authorized.

## 🧪 Technical Logic
Aegis utilizes Symmetric AES Encryption (Fernet). The key-derivation pipeline follows this path:

**Identity:** Capture Hardware UUID/MAC.

**Transformation:** String Encode -> SHA-256 Digest.

**Standardization:** URL-Safe Base64 Encoding.

**Application:** Fernet Cipher Initialization.

## 🛡️ Security Disclaimer
This project is intended for educational purposes and personal data obfuscation. While it utilizes strong AES encryption, the "Self-Destruct" mechanism is software-based. Professional forensic tools or manual script modification may bypass certain local security checks.
