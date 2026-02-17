"""
Cryptography Algorithms Web Application
A Flask-based web interface for various cryptographic operations.

This application provides a user-friendly interface to:
- Encrypt/Decrypt data using AES (symmetric)
- Encrypt/Decrypt data using RSA (asymmetric)
- Hash passwords and verify them using SHA-256
"""

from flask import Flask, render_template, request, jsonify, session
from crypto_utils import AESEncryptor, RSAEncryptor, SHA256Hasher
import secrets
import os

# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

app = Flask(__name__)
# Secret key for session management and CSRF protection
app.secret_key = secrets.token_hex(32)

# Global dictionaries to store keys during user session
# In production, use secure session storage or database
user_keys = {}


# ============================================================================
# ROUTE: HOME PAGE
# ============================================================================

@app.route('/')
def index():
    """
    Render the main page with the cryptography interface
    
    Returns:
        Rendered HTML template with the user interface
    """
    return render_template('index.html')


# ============================================================================
# ROUTE: AES KEY GENERATION
# ============================================================================

@app.route('/api/generate-aes-key', methods=['POST'])
def generate_aes_key():
    """
    Generate a new random AES key
    
    Returns:
        JSON with generated key
    """
    try:
        key = AESEncryptor.generate_key()
        return jsonify({
            'status': 'success',
            'key': key,
            'message': 'AES-256 key generated successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error generating AES key: {str(e)}'
        }), 500


# ============================================================================
# ROUTE: AES ENCRYPTION
# ============================================================================

@app.route('/api/aes-encrypt', methods=['POST'])
def aes_encrypt():
    """
    Encrypt plaintext using AES-256-GCM
    
    Expected JSON payload:
        - plaintext (str): Text to encrypt
        - key (str): Base64 encoded AES key
    
    Returns:
        JSON with ciphertext, nonce, and tag
    """
    try:
        data = request.json
        plaintext = data.get('plaintext', '').strip()
        key = data.get('key', '').strip()
        
        # Validate input
        if not plaintext:
            return jsonify({
                'status': 'error',
                'message': 'Plaintext cannot be empty'
            }), 400
        
        if not key:
            return jsonify({
                'status': 'error',
                'message': 'AES key is required'
            }), 400
        
        # Perform encryption
        result = AESEncryptor.encrypt(plaintext, key)
        
        if result['status'] == 'error':
            return jsonify(result), 400
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Encryption error: {str(e)}'
        }), 500


# ============================================================================
# ROUTE: AES DECRYPTION
# ============================================================================

@app.route('/api/aes-decrypt', methods=['POST'])
def aes_decrypt():
    """
    Decrypt ciphertext using AES-256-GCM
    
    Expected JSON payload:
        - ciphertext (str): Base64 encoded ciphertext
        - key (str): Base64 encoded AES key
        - nonce (str): Base64 encoded nonce
        - tag (str): Base64 encoded authentication tag
    
    Returns:
        JSON with decrypted plaintext
    """
    try:
        data = request.json
        ciphertext = data.get('ciphertext', '').strip()
        key = data.get('key', '').strip()
        nonce = data.get('nonce', '').strip()
        tag = data.get('tag', '').strip()
        
        # Validate input
        if not all([ciphertext, key, nonce, tag]):
            return jsonify({
                'status': 'error',
                'message': 'Ciphertext, key, nonce, and tag are all required'
            }), 400
        
        # Perform decryption
        result = AESEncryptor.decrypt(ciphertext, key, nonce, tag)
        
        if result['status'] == 'error':
            return jsonify(result), 400
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Decryption error: {str(e)}'
        }), 500


# ============================================================================
# ROUTE: RSA KEY PAIR GENERATION
# ============================================================================

@app.route('/api/generate-rsa-keypair', methods=['POST'])
def generate_rsa_keypair():
    """
    Generate a new RSA 2048-bit key pair
    
    Returns:
        JSON with public and private keys
        
    Note:
        Keys are stored in session to maintain across requests
    """
    try:
        result = RSAEncryptor.generate_keypair(key_size=2048)
        
        if result['status'] == 'error':
            return jsonify(result), 400
        
        # Store in session for subsequent operations
        session['rsa_public_key'] = result['public_key']
        session['rsa_private_key'] = result['private_key']
        session.modified = True
        
        return jsonify({
            'status': 'success',
            'public_key': result['public_key'],
            'private_key': result['private_key'],
            'message': 'RSA 2048-bit key pair generated successfully'
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error generating RSA key pair: {str(e)}'
        }), 500


# ============================================================================
# ROUTE: RSA ENCRYPTION
# ============================================================================

@app.route('/api/rsa-encrypt', methods=['POST'])
def rsa_encrypt():
    """
    Encrypt plaintext using RSA public key
    
    Expected JSON payload:
        - plaintext (str): Text to encrypt (max ~245 characters)
        - public_key (str): RSA public key in PEM format
    
    Returns:
        JSON with base64 encoded ciphertext
    """
    try:
        data = request.json
        plaintext = data.get('plaintext', '').strip()
        public_key = data.get('public_key', '').strip()
        
        # Validate input
        if not plaintext:
            return jsonify({
                'status': 'error',
                'message': 'Plaintext cannot be empty'
            }), 400
        
        if not public_key:
            return jsonify({
                'status': 'error',
                'message': 'Public key is required'
            }), 400
        
        # Perform encryption
        result = RSAEncryptor.encrypt(plaintext, public_key)
        
        if result['status'] == 'error':
            return jsonify(result), 400
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Encryption error: {str(e)}'
        }), 500


# ============================================================================
# ROUTE: RSA DECRYPTION
# ============================================================================

@app.route('/api/rsa-decrypt', methods=['POST'])
def rsa_decrypt():
    """
    Decrypt ciphertext using RSA private key
    
    Expected JSON payload:
        - ciphertext (str): Base64 encoded ciphertext
        - private_key (str): RSA private key in PEM format
    
    Returns:
        JSON with decrypted plaintext
    """
    try:
        data = request.json
        ciphertext = data.get('ciphertext', '').strip()
        private_key = data.get('private_key', '').strip()
        
        # Validate input
        if not ciphertext:
            return jsonify({
                'status': 'error',
                'message': 'Ciphertext cannot be empty'
            }), 400
        
        if not private_key:
            return jsonify({
                'status': 'error',
                'message': 'Private key is required'
            }), 400
        
        # Perform decryption
        result = RSAEncryptor.decrypt(ciphertext, private_key)
        
        if result['status'] == 'error':
            return jsonify(result), 400
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Decryption error: {str(e)}'
        }), 500


# ============================================================================
# ROUTE: SHA-256 HASHING (For Password Storage)
# ============================================================================

@app.route('/api/sha256-hash-password', methods=['POST'])
def sha256_hash_password():
    """
    Generate SHA-256 hash of a password with random salt
    
    Expected JSON payload:
        - password (str): Password to hash
    
    Returns:
        JSON with hash, salt, and combined hash
        
    Note:
        The combined hash (salt$hash) should be stored in database
        along with the original salt for later verification
    """
    try:
        data = request.json
        password = data.get('password', '').strip()
        
        # Validate input
        if not password:
            return jsonify({
                'status': 'error',
                'message': 'Password cannot be empty'
            }), 400
        
        # Perform hashing with random salt
        result = SHA256Hasher.hash_password(password)
        
        if result['status'] == 'error':
            return jsonify(result), 400
        
        return jsonify({
            'status': 'success',
            'hash': result['hash'],
            'salt': result['salt'],
            'full_hash': result['full_hash'],
            'message': 'Password hashed successfully with random salt'
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Hashing error: {str(e)}'
        }), 500


# ============================================================================
# ROUTE: SHA-256 PASSWORD VERIFICATION
# ============================================================================

@app.route('/api/sha256-verify-password', methods=['POST'])
def sha256_verify_password():
    """
    Verify a password against a stored hash
    
    Expected JSON payload:
        - password (str): Password to verify
        - stored_hash (str): Previously stored hash in format "salt$hash"
    
    Returns:
        JSON with match result (true/false)
        
    Algorithm:
        1. Extract salt from stored hash
        2. Hash the provided password with extracted salt
        3. Compare with stored hash value
    """
    try:
        data = request.json
        password = data.get('password', '').strip()
        stored_hash = data.get('stored_hash', '').strip()
        
        # Validate input
        if not password:
            return jsonify({
                'status': 'error',
                'message': 'Password cannot be empty'
            }), 400
        
        if not stored_hash:
            return jsonify({
                'status': 'error',
                'message': 'Stored hash is required'
            }), 400
        
        # Perform verification
        result = SHA256Hasher.verify_password(password, stored_hash)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Verification error: {str(e)}'
        }), 500


# ============================================================================
# ROUTE: SHA-256 DATA HASHING (For Data Integrity)
# ============================================================================

@app.route('/api/sha256-hash-data', methods=['POST'])
def sha256_hash_data():
    """
    Generate SHA-256 hash of data (for integrity checking, not passwords)
    
    Expected JSON payload:
        - data (str): Data to hash
    
    Returns:
        JSON with SHA-256 hash hexdigest
        
    Use case:
        - Verify file integrity
        - Create checksums
        - Ensure data hasn't been tampered with
    """
    try:
        data = request.json
        input_data = data.get('data', '').strip()
        
        # Validate input
        if not input_data:
            return jsonify({
                'status': 'error',
                'message': 'Data cannot be empty'
            }), 400
        
        # Perform hashing
        result = SHA256Hasher.hash_data(input_data)
        
        if result['status'] == 'error':
            return jsonify(result), 400
        
        return jsonify({
            'status': 'success',
            'hash': result['hash'],
            'message': 'Data hashed successfully'
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Hashing error: {str(e)}'
        }), 500


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors"""
    return jsonify({'status': 'error', 'message': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server errors"""
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    """
    Run the Flask development server
    
    WARNING: This is for development only. For production:
    - Use a production WSGI server (Gunicorn, uWSGI)
    - Set DEBUG=False
    - Use environment variables for configuration
    - Enable HTTPS/SSL
    - Add proper CORS configuration
    """
    # Enable debug mode for development (auto-reload and better error pages)
    app.run(
        host='127.0.0.1',      # Listen on localhost
        port=5000,              # Standard Flask development port
        debug=True,             # Auto-reload on code changes
        use_reloader=True       # Enable auto-reload
    )
