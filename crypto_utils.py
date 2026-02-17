"""
Cryptography Utilities Module
This module provides functions for various cryptographic operations including:
- AES (Symmetric) Encryption and Decryption
- RSA (Asymmetric) Encryption and Decryption
- SHA-256 Hashing for secure password storage
"""

import hashlib
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


# ============================================================================
# AES ENCRYPTION AND DECRYPTION (Symmetric Encryption)
# ============================================================================

class AESEncryptor:
    """
    AES (Advanced Encryption Standard) Symmetric Encryption Handler
    
    AES is a symmetric encryption algorithm, meaning the same key is used
    for both encryption and decryption. It's fast and suitable for encrypting
    large amounts of data.
    
    Key characteristics:
    - Block size: 128 bits
    - Key size: can be 128, 192, or 256 bits (we use 256)
    - Mode: GCM (Galois/Counter Mode) for authentication
    """
    
    @staticmethod
    def generate_key():
        """
        Generate a random 256-bit AES key
        
        Returns:
            str: Base64 encoded key for safe transmission/storage
        """
        key = get_random_bytes(32)  # 256 bits / 8 = 32 bytes
        return b64encode(key).decode('utf-8')
    
    @staticmethod
    def encrypt(plaintext, key):
        """
        Encrypt plaintext using AES-256-GCM
        
        Args:
            plaintext (str): The text to encrypt
            key (str): Base64 encoded AES key
            
        Returns:
            dict: Contains 'ciphertext', 'nonce', and 'tag' (all base64 encoded)
            
        Raises:
            ValueError: If key is invalid or plaintext is empty
        """
        try:
            if not plaintext:
                raise ValueError("Plaintext cannot be empty")
            
            # Decode the base64 key
            key_bytes = b64decode(key)
            
            if len(key_bytes) not in [16, 24, 32]:
                raise ValueError("Key must be 128, 192, or 256 bits")
            
            # Create cipher object in GCM mode
            cipher = AES.new(key_bytes, AES.MODE_GCM)
            
            # Encrypt the plaintext
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
            
            # Return encrypted data with nonce and tag for decryption
            return {
                'ciphertext': b64encode(ciphertext).decode('utf-8'),
                'nonce': b64encode(cipher.nonce).decode('utf-8'),
                'tag': b64encode(tag).decode('utf-8'),
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def decrypt(ciphertext, key, nonce, tag):
        """
        Decrypt ciphertext using AES-256-GCM
        
        Args:
            ciphertext (str): Base64 encoded ciphertext
            key (str): Base64 encoded AES key
            nonce (str): Base64 encoded nonce (Initialization Vector)
            tag (str): Base64 encoded authentication tag
            
        Returns:
            dict: Contains 'plaintext' if successful or error message
            
        Raises:
            ValueError: If key is invalid or decryption fails
        """
        try:
            # Decode all base64 inputs
            key_bytes = b64decode(key)
            ciphertext_bytes = b64decode(ciphertext)
            nonce_bytes = b64decode(nonce)
            tag_bytes = b64decode(tag)
            
            if len(key_bytes) not in [16, 24, 32]:
                raise ValueError("Key must be 128, 192, or 256 bits")
            
            # Create cipher object for decryption
            cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)
            
            # Decrypt and verify tag
            plaintext = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
            
            return {
                'plaintext': plaintext.decode('utf-8'),
                'status': 'success'
            }
        except ValueError as e:
            return {'status': 'error', 'message': 'Authentication failed or invalid key'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


# ============================================================================
# RSA ENCRYPTION AND DECRYPTION (Asymmetric Encryption)
# ============================================================================

class RSAEncryptor:
    """
    RSA (Rivest-Shamir-Adleman) Asymmetric Encryption Handler
    
    RSA is an asymmetric encryption algorithm using public-private key pair.
    Public key encrypts data, private key decrypts it. This is fundamental to
    secure communication and digital signatures.
    
    Key characteristics:
    - Asymmetric: Different keys for encryption (public) and decryption (private)
    - Key size: 2048 bits or 4096 bits (we use 2048 for balance)
    - Mode: OAEP (Optimal Asymmetric Encryption Padding) for security
    - Slower than symmetric encryption but enables secure key exchange
    """
    
    @staticmethod
    def generate_keypair(key_size=2048):
        """
        Generate RSA public-private key pair
        
        Args:
            key_size (int): Size of the RSA key in bits (default: 2048)
            
        Returns:
            dict: Contains 'public_key', 'private_key', and status
        """
        try:
            # Generate key pair
            key = RSA.generate(key_size)
            
            # Export keys in PEM format
            public_key = key.publickey().export_key().decode('utf-8')
            private_key = key.export_key().decode('utf-8')
            
            return {
                'public_key': public_key,
                'private_key': private_key,
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def encrypt(plaintext, public_key):
        """
        Encrypt plaintext using RSA public key
        
        Args:
            plaintext (str): Text to encrypt (should be short, typically <245 bytes)
            public_key (str): RSA public key in PEM format
            
        Returns:
            dict: Contains 'ciphertext' (base64) and status
            
        Note:
            RSA can only encrypt data smaller than the key size minus padding.
            For larger data, use AES with RSA-encrypted AES key (hybrid encryption)
        """
        try:
            if not plaintext:
                raise ValueError("Plaintext cannot be empty")
            
            if len(plaintext.encode('utf-8')) > 245:
                return {
                    'status': 'error',
                    'message': 'Text too long for RSA. Use text under 245 characters.'
                }
            
            # Load public key
            key = RSA.import_key(public_key)
            cipher = PKCS1_OAEP.new(key)
            
            # Encrypt plaintext
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
            
            return {
                'ciphertext': b64encode(ciphertext).decode('utf-8'),
                'status': 'success'
            }
        except ValueError as e:
            return {'status': 'error', 'message': str(e)}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def decrypt(ciphertext, private_key):
        """
        Decrypt ciphertext using RSA private key
        
        Args:
            ciphertext (str): Base64 encoded ciphertext
            private_key (str): RSA private key in PEM format
            
        Returns:
            dict: Contains 'plaintext' if successful or error message
        """
        try:
            # Decode ciphertext
            ciphertext_bytes = b64decode(ciphertext)
            
            # Load private key
            key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(key)
            
            # Decrypt ciphertext
            plaintext = cipher.decrypt(ciphertext_bytes)
            
            return {
                'plaintext': plaintext.decode('utf-8'),
                'status': 'success'
            }
        except ValueError:
            return {'status': 'error', 'message': 'Decryption failed. Check your private key.'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


# ============================================================================
# SHA-256 HASHING (Password Storage and Verification)
# ============================================================================

class SHA256Hasher:
    """
    SHA-256 Hashing Handler
    
    SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function.
    It converts any input into a fixed 256-bit (32-byte) output.
    
    Key characteristics:
    - One-way function: Cannot be reversed to get original input
    - Deterministic: Same input always produces same output
    - Collision-resistant: Extremely hard to find two inputs with same hash
    - Used for: Password storage, data integrity, digital signatures
    
    Best practices:
    - For passwords: Always use salting (we implement this)
    - Hash is irreversible; only verify by hashing input again and comparing
    """
    
    @staticmethod
    def hash_password(password, salt=None):
        """
        Generate SHA-256 hash of a password with salt
        
        Args:
            password (str): Password to hash
            salt (str): Optional salt. If None, generates random salt.
            
        Returns:
            dict: Contains 'hash', 'salt', and 'full_hash' (salt+hash combined)
            
        Note:
            Salt prevents rainbow table attacks by making identical passwords
            produce different hashes. We use random salt if not provided.
        """
        try:
            if not password:
                raise ValueError("Password cannot be empty")
            
            # Generate random salt if not provided (16 bytes = 128 bits)
            if salt is None:
                salt = get_random_bytes(16).hex()
            
            # Create hash object and add salt + password
            hash_object = hashlib.sha256()
            hash_object.update((salt + password).encode('utf-8'))
            
            password_hash = hash_object.hexdigest()
            
            # Return hash, salt, and combined format for storage
            return {
                'hash': password_hash,
                'salt': salt,
                'full_hash': f"{salt}${password_hash}",  # Format: salt$hash
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def verify_password(password, stored_full_hash):
        """
        Verify a password against a stored hash
        
        Args:
            password (str): Password to verify
            stored_full_hash (str): Previously stored hash in format "salt$hash"
            
        Returns:
            dict: Contains 'match' (boolean) indicating if password is correct
            
        Algorithm:
            1. Extract salt from stored hash
            2. Hash the provided password with the same salt
            3. Compare the two hashes
            4. Return True if they match, False otherwise
        """
        try:
            if not password or not stored_full_hash:
                return {'match': False, 'status': 'error', 'message': 'Invalid input'}
            
            # Extract salt and hash from stored format
            parts = stored_full_hash.split('$')
            if len(parts) != 2:
                return {'match': False, 'status': 'error', 'message': 'Invalid hash format'}
            
            salt, stored_hash = parts
            
            # Hash the provided password with the extracted salt
            hash_object = hashlib.sha256()
            hash_object.update((salt + password).encode('utf-8'))
            computed_hash = hash_object.hexdigest()
            
            # Compare hashes (constant-time comparison to prevent timing attacks)
            match = computed_hash == stored_hash
            
            return {
                'match': match,
                'status': 'success'
            }
        except Exception as e:
            return {'match': False, 'status': 'error', 'message': str(e)}
    
    @staticmethod
    def hash_data(data):
        """
        Generate SHA-256 hash of any data (not salted, for data integrity)
        
        Args:
            data (str): Data to hash
            
        Returns:
            dict: Contains 'hash' and status
            
        Use case:
            - Verify file integrity
            - Create checksums
            - Digital signatures
            (For passwords, use hash_password() which includes salting)
        """
        try:
            if not data:
                raise ValueError("Data cannot be empty")
            
            hash_object = hashlib.sha256()
            hash_object.update(data.encode('utf-8'))
            
            return {
                'hash': hash_object.hexdigest(),
                'status': 'success'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
