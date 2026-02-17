# Cryptography Algorithms Implementation

A professional, feature-rich web application for learning and implementing cryptographic algorithms. Built with Python Flask and featuring AES, RSA, and SHA-256 encryption methods.

**Live Demo Features:**
- 🔐 AES-256 Symmetric Encryption/Decryption (GCM Mode)
- 🔑 RSA Asymmetric Encryption/Decryption (OAEP Padding)
- 🔒 SHA-256 Hashing with Salt (Password Storage & Verification)
- 🎨 Clean, responsive Bootstrap UI
- ✅ Full error handling and validation
- 📱 Mobile-friendly interface

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Installation & Setup](#installation--setup)
3. [How to Run](#how-to-run)
4. [API Endpoints](#api-endpoints)
5. [Algorithm Explanations](#algorithm-explanations)
6. [Usage Examples](#usage-examples)
7. [Security Considerations](#security-considerations)
8. [Code Architecture](#code-architecture)
9. [Troubleshooting](#troubleshooting)
10. [Future Enhancements](#future-enhancements)

---

## Project Structure

```
Cryptography/
│
├── app.py                      # Flask main application (routes & server)
├── crypto_utils.py             # Core cryptographic functions
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
└── templates/
    └── index.html              # Web UI (HTML + Bootstrap + JavaScript)
```

### File Descriptions

**app.py** - Flask Web Application
- Defines all API routes for encryption/decryption/hashing
- Handles HTTP requests from the frontend
- Implements error handling and validation
- Uses JSON for request/response communication
- ~380 lines of well-documented code

**crypto_utils.py** - Cryptography Core Logic
- `AESEncryptor` class: AES-256-GCM encryption/decryption
- `RSAEncryptor` class: RSA-2048 encryption/decryption with OAEP
- `SHA256Hasher` class: Password hashing with salt and password verification
- ~500 lines with comprehensive documentation
- Uses PyCryptodome library for cryptocr operations

**templates/index.html** - Web User Interface
- Responsive Bootstrap 5 design
- Organized tabs for each algorithm
- Real-time form validation
- Copy-to-clipboard functionality
- Information section explaining each algorithm
- ~800 lines of HTML + CSS + JavaScript

---

## Installation & Setup

### Prerequisites

- **Python 3.8+** installed on your system
- **pip** (Python package manager)
- **Git** (optional, for cloning)

### Step 1: Clone or Download the Project

```bash
# Clone from repository (if available)
git clone https://github.com/yourusername/cryptography-algorithms.git
cd Cryptography

# Or download and extract the ZIP file manually
```

### Step 2: Create a Virtual Environment (Recommended)

Creating a virtual environment isolates project dependencies:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- **Flask** - Web framework
- **PyCryptodome** - Cryptography library (AES, RSA)
- **Werkzeug** - WSGI utilities

### Step 4: Verify Installation

```bash
python -c "from Crypto.Cipher import AES; print('PyCryptodome installed successfully')"
python -c "import flask; print('Flask installed successfully')"
```

---

## How to Run

### Start the Flask Development Server

```bash
# Make sure virtual environment is activated
python app.py
```

### Access the Application

Open your web browser and navigate to:
```
http://localhost:5000
```

You should see the Cryptography Algorithms web interface.

### Stop the Server

Press `Ctrl+C` in your terminal to stop the server.

---

## API Endpoints

All endpoints accept `POST` requests with JSON data and return JSON responses.

### AES Encryption Endpoints

#### Generate AES Key
```
POST /api/generate-aes-key
Response: { "status": "success", "key": "base64_encoded_key" }
```

#### Encrypt with AES
```
POST /api/aes-encrypt
Body: { "plaintext": "text", "key": "base64_key" }
Response: { 
    "status": "success", 
    "ciphertext": "base64_ciphertext",
    "nonce": "base64_nonce",
    "tag": "base64_tag"
}
```

#### Decrypt with AES
```
POST /api/aes-decrypt
Body: { 
    "ciphertext": "base64_ciphertext",
    "key": "base64_key",
    "nonce": "base64_nonce",
    "tag": "base64_tag"
}
Response: { "status": "success", "plaintext": "decrypted_text" }
```

### RSA Encryption Endpoints

#### Generate RSA Keypair
```
POST /api/generate-rsa-keypair
Response: { 
    "status": "success", 
    "public_key": "PEM_format_public_key",
    "private_key": "PEM_format_private_key"
}
```

#### Encrypt with RSA
```
POST /api/rsa-encrypt
Body: { "plaintext": "text (max 245 chars)", "public_key": "PEM_key" }
Response: { "status": "success", "ciphertext": "base64_ciphertext" }
```

#### Decrypt with RSA
```
POST /api/rsa-decrypt
Body: { "ciphertext": "base64_ciphertext", "private_key": "PEM_key" }
Response: { "status": "success", "plaintext": "decrypted_text" }
```

### SHA-256 Hashing Endpoints

#### Hash Password (with Salt)
```
POST /api/sha256-hash-password
Body: { "password": "password_string" }
Response: {
    "status": "success",
    "salt": "random_salt_hex",
    "hash": "sha256_hash",
    "full_hash": "salt$hash"  // Store this in database
}
```

#### Verify Password
```
POST /api/sha256-verify-password
Body: { "password": "password_to_verify", "stored_hash": "salt$hash" }
Response: { "match": true/false, "status": "success" }
```

#### Hash Data (for integrity)
```
POST /api/sha256-hash-data
Body: { "data": "any_data_string" }
Response: { "status": "success", "hash": "sha256_hash" }
```

---

## Algorithm Explanations

### 1. AES (Advanced Encryption Standard) - Symmetric Encryption

**What is it?**
AES is a symmetric encryption algorithm, meaning you use the same key to encrypt and decrypt data.

**Key Characteristics:**
- **Block Size**: 128 bits
- **Key Size**: 256 bits (in this implementation)
- **Mode**: GCM (Galois/Counter Mode) - provides both encryption and authentication
- **Speed**: Very fast, suitable for large data volumes
- **Security Level**: Considered secure for most applications

**How it works:**
1. You have a secret key (256 bits = 32 bytes)
2. Plaintext is divided into blocks and encrypted using the key
3. The receiver uses the same key to decrypt
4. GCM mode also generates a "tag" for authenticating the message

**Usage:**
```python
# Client has key: "my-secret-key-base64"
plaintext = "Hello, this is secret!"
ciphertext, nonce, tag = encrypt_aes(plaintext, key)

# Receiver has same key
plaintext = decrypt_aes(ciphertext, key, nonce, tag)
```

**Security:** Only someone with the secret key can decrypt your data.

**Use Cases:** File encryption, secure messaging, database encryption

---

### 2. RSA (Rivest-Shamir-Adleman) - Asymmetric Encryption

**What is it?**
RSA uses a public-private key pair. The public key encrypts, the private key decrypts.

**Key Characteristics:**
- **Key Type**: Asymmetric (two different keys)
- **Key Size**: 2048 bits (in this implementation)
- **Mode**: OAEP (Optimal Asymmetric Encryption Padding)
- **Maximum Data**: ~245 bytes per encryption
- **Speed**: Slower than AES but enables secure key exchange

**How it works:**
1. Generate two mathematically related keys: Public and Private
2. Public key can be shared with everyone
3. Only the Private key can decrypt messages encrypted with the Public key
4. Based on the mathematical difficulty of factoring large prime numbers

**Usage:**
```python
# Alice generates keypair
public_key, private_key = generate_keypair()

# Alice shares public_key with Bob
# Bob encrypts message using Alice's public key
ciphertext = encrypt_rsa(message, alice_public_key)

# Only Alice can decrypt with her private key
plaintext = decrypt_rsa(ciphertext, alice_private_key)
```

**Security:** The public key cannot decrypt data - only the secret private key can.

**Use Cases:** 
- Secure key exchange
- Digital signatures
- Email encryption (PGP)
- HTTPS/SSL certificates

---

### 3. SHA-256 (Secure Hash Algorithm 256-bit) - Hashing

**What is it?**
SHA-256 converts any input into a fixed 256-bit (64 hex character) output. It's one-way - you cannot reverse the hash to get the original input.

**Key Characteristics:**
- **Output Size**: 256 bits (64 hexadecimal characters)
- **Reversible**: NO - cannot get input from hash
- **Deterministic**: Same input always produces same hash
- **Collision Resistant**: Extremely hard to find two inputs with same hash
- **Speed**: Very fast

**Hash Properties:**
- **Deterministic**: `hash("hello")` always produces `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`
- **One-way**: Cannot reverse to get "hello" from the hash
- **Avalanche Effect**: Tiny change in input completely changes hash
  - `hash("hello")` = `2cf24...`
  - `hash("hallo")` = `d3751...` (completely different!)

**How it works (Simplified):**
1. Input data is processed through mathematical functions
2. Data is mixed and transformed multiple rounds
3. Final output is 256-bit hash

**Password Hashing with Salt:**
```
Password: "mypassword123"
Salt: "a7f3k9x2m1" (random, unique per password)
Hashed: hash("a7f3k9x2m1" + "mypassword123")
Stored: "a7f3k9x2m1$hash_result"
```

**Verification Process:**
```
User enters: "mypassword123"
Retrieved from DB: "a7f3k9x2m1$hash_result"
Extract salt: "a7f3k9x2m1"
Compute: hash("a7f3k9x2m1" + "mypassword123")
Compare with stored hash
Match? Password correct!
```

**Why Salt?**
- Prevents rainbow table attacks (precomputed hash tables)
- Makes identical passwords have different hashes
- Each password gets unique salt

**Use Cases:**
- Password storage (NEVER store plain passwords!)
- File integrity verification
- Git commit hashes
- Digital signatures
- Blockchain and cryptocurrency

---

## Usage Examples

### Example 1: Encrypting a Message with AES

**Frontend (JavaScript):**
```javascript
// Step 1: Generate AES key
const keyResponse = await fetch('/api/generate-aes-key', {
    method: 'POST'
});
const keyData = await keyResponse.json();
const aesKey = keyData.key;

// Step 2: Encrypt message
const encryptResponse = await fetch('/api/aes-encrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        plaintext: "Hello, World!",
        key: aesKey
    })
});
const encrypted = await encryptResponse.json();
console.log("Ciphertext:", encrypted.ciphertext);
console.log("Nonce:", encrypted.nonce);
console.log("Tag:", encrypted.tag);
```

**Backend (Python):**
```python
from crypto_utils import AESEncryptor

# Generate key
key = AESEncryptor.generate_key()
print(f"Key: {key}")

# Encrypt
result = AESEncryptor.encrypt("Hello, World!", key)
print(f"Ciphertext: {result['ciphertext']}")
print(f"Nonce: {result['nonce']}")
print(f"Tag: {result['tag']}")

# Decrypt
decrypted = AESEncryptor.decrypt(
    result['ciphertext'],
    key,
    result['nonce'],
    result['tag']
)
print(f"Decrypted: {decrypted['plaintext']}")  # "Hello, World!"
```

### Example 2: RSA Key Exchange

**Backend (Python):**
```python
from crypto_utils import RSAEncryptor

# Generate keypair
keypair = RSAEncryptor.generate_keypair()
public_key = keypair['public_key']
private_key = keypair['private_key']

# Encrypt with public key
encrypted = RSAEncryptor.encrypt("Secret message", public_key)
print(f"Encrypted: {encrypted['ciphertext']}")

# Only private key can decrypt
decrypted = RSAEncryptor.decrypt(encrypted['ciphertext'], private_key)
print(f"Decrypted: {decrypted['plaintext']}")  # "Secret message"
```

### Example 3: Secure Password Storage

**Backend (Python):**
```python
from crypto_utils import SHA256Hasher

# User creates password
password = "MySecurePassword123!"

# Hash it with random salt
hash_result = SHA256Hasher.hash_password(password)
stored_hash = hash_result['full_hash']

# Store in database: stored_hash = "a7f3k9x2m1$d3751..."

# Later, user logs in with password "MySecurePassword123!"
verification = SHA256Hasher.verify_password(password, stored_hash)
print(verification['match'])  # True - Password is correct!

# User tries wrong password
wrong = SHA256Hasher.verify_password("WrongPassword", stored_hash)
print(wrong['match'])  # False - Access denied!
```

---

## Security Considerations

### ✅ Best Practices Implemented

1. **AES-256 with GCM Mode**
   - 256-bit key provides strong encryption
   - GCM provides authenticated encryption (prevents tampering)
   - Random nonce for each encryption

2. **RSA-2048 with OAEP Padding**
   - 2048-bit key is cryptographically secure
   - OAEP padding prevents padding oracle attacks
   - Uses randomized encryption (same plaintext produces different ciphertext)

3. **SHA-256 with Salt**
   - Random 128-bit salt per password
   - Prevents rainbow table attacks
   - Each password gets unique hash

### ⚠️ Security Warnings

1. **This is a Learning/Demo Tool**
   - Not intended for production use with real sensitive data
   - Use professional cryptography libraries in production

2. **Private Keys**
   - Never share RSA private keys
   - Store private keys securely (encrypted or in key management system)
   - Never commit private keys to version control

3. **Key Management**
   - AES keys should be stored securely
   - Rotate keys periodically
   - Use environment variables or secure vaults for key storage
   - Never hardcode keys in source code

4. **HTTPS in Production**
   - Always use HTTPS/SSL to encrypt data in transit
   - This prevents man-in-the-middle attacks

5. **Password Storage**
   - Always use salt (prevents rainbow tables)
   - Use strong hashing algorithms (SHA-256 is good, bcrypt/Argon2 are better)
   - Use slow hashing for passwords to prevent brute force
   - Never transmit passwords in plain text

6. **Input Validation**
   - Always validate and sanitize user input
   - This application validates input size, format, etc.

7. **Error Handling**
   - Never expose sensitive information in error messages
   - This application provides generic error messages

---

## Code Architecture

### Class Structure

**AESEncryptor (crypto_utils.py)**
```python
class AESEncryptor:
    @staticmethod
    def generate_key()
        # Generate random 256-bit AES key
    
    @staticmethod
    def encrypt(plaintext, key)
        # Encrypt using AES-256-GCM
    
    @staticmethod
    def decrypt(ciphertext, key, nonce, tag)
        # Decrypt using AES-256-GCM
```

**RSAEncryptor (crypto_utils.py)**
```python
class RSAEncryptor:
    @staticmethod
    def generate_keypair(key_size=2048)
        # Generate RSA 2048-bit keypair
    
    @staticmethod
    def encrypt(plaintext, public_key)
        # Encrypt using RSA-OAEP
    
    @staticmethod
    def decrypt(ciphertext, private_key)
        # Decrypt using RSA-OAEP
```

**SHA256Hasher (crypto_utils.py)**
```python
class SHA256Hasher:
    @staticmethod
    def hash_password(password, salt=None)
        # Hash password with salt
    
    @staticmethod
    def verify_password(password, stored_full_hash)
        # Verify password against stored hash
    
    @staticmethod
    def hash_data(data)
        # Hash data for integrity checking
```

### Request Flow

```
1. User interacts with index.html (web browser)
   ↓
2. JavaScript sends POST request to Flask API (app.py)
   ↓
3. Flask route validates input and calls crypto_utils.py
   ↓
4. crypto_utils.py performs cryptographic operation
   ↓
5. Result is returned as JSON to JavaScript
   ↓
6. JavaScript displays result in web interface
```

---

## Troubleshooting

### Issue: "PyCryptodome not found"
**Solution:**
```bash
pip install PyCryptodome
```

### Issue: "Flask not found"
**Solution:**
```bash
pip install Flask
```

### Issue: "Port 5000 already in use"
**Solution:** Change port in app.py:
```python
if __name__ == '__main__':
    app.run(port=5001)  # Use different port
```

### Issue: "Cannot decrypt - authentication failed"
**Causes:**
- Using wrong key
- Wrong nonce or tag
- Data was modified after encryption

**Solution:**
- Ensure you're using the exact same key
- Make sure nonce and tag are correct (copy-paste entire value)
- Re-encrypt the data

### Issue: "RSA text too long"
**Cause:** RSA can only encrypt ~245 bytes with 2048-bit key
**Solution:**
- Use shorter text
- For longer data, use hybrid encryption (RSA + AES)
- Implement hybrid encryption where RSA encrypts AES key, AES encrypts data

### Issue: Browser shows "Connection refused"
**Solution:**
- Ensure Flask server is running (`python app.py`)
- Check that you're accessing `http://localhost:5000`
- Look for errors in terminal where you ran `python app.py`

---

## Future Enhancements

### Planned Features

1. **Hybrid Encryption**
   - Use RSA to encrypt AES key
   - Use AES to encrypt large data
   - Combines benefits of both algorithms

2. **Digital Signatures**
   - Sign data with RSA private key
   - Verify signature with RSA public key
   - Ensures authenticity and non-repudiation

3. **File Encryption**
   - Encrypt entire files
   - Handle binary data
   - Progress indication for large files

4. **Key Management**
   - Save/load keys from files
   - Export/import key pairs
   - Key derivation functions

5. **Authentication**
   - User login/registration
   - Key storage per user
   - Activity logging

6. **Advanced Algorithms**
   - ECC (Elliptic Curve Cryptography)
   - HMAC (Hash-based Message Authentication)
   - Argon2 (password hashing)

7. **API Documentation**
   - Swagger/OpenAPI documentation
   - Client SDKs for various languages

8. **Performance**
   - Caching for key generation
   - Async processing for large operations
   - Progress streaming

---

## Contributing

This project is designed for learning purposes. Contributions are welcome!

**To contribute:**
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is open source and available under the MIT License.

---

## Author & Contact

**Project:** Cryptography Algorithms Implementation  
**Version:** 1.0.0  
**Created:** 2024  

For questions, issues, or suggestions, please open an issue on the project repository.

---

## Disclaimer

This project is for **educational purposes only**. While the cryptographic algorithms implemented are industry-standard and secure when used correctly, this demo application should not be used for protecting real sensitive data in production environments.

For production use:
- Use dedicated security libraries and services
- Conduct security audits
- Follow OWASP guidelines
- Use professional cryptography frameworks

---

## References

- [NIST AES Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [RSA Cryptography Specifications](https://tools.ietf.org/html/rfc3447)
- [SHA-256 Documentation](https://en.wikipedia.org/wiki/SHA-2)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

**Happy Learning! 🔐**
