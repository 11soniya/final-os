"""
Encryption utilities for file storage
"""
from cryptography.fernet import Fernet
import base64
import hashlib
from config import ENCRYPTION_KEY


def get_fernet_key() -> bytes:
    """Convert the encryption key to a proper Fernet key"""
    # Ensure the key is 32 bytes and base64 encoded
    key = ENCRYPTION_KEY.encode()[:32]
    # Pad if necessary
    key = key.ljust(32, b'0')
    return base64.urlsafe_b64encode(key)


def encrypt_file(data: bytes) -> bytes:
    """Encrypt file data using Fernet (AES-128 in CBC mode)"""
    fernet = Fernet(get_fernet_key())
    return fernet.encrypt(data)


def decrypt_file(encrypted_data: bytes) -> bytes:
    """Decrypt file data"""
    fernet = Fernet(get_fernet_key())
    return fernet.decrypt(encrypted_data)


def calculate_checksum(data: bytes) -> str:
    """Calculate SHA256 checksum of data"""
    return hashlib.sha256(data).hexdigest()


def verify_checksum(data: bytes, expected_checksum: str) -> bool:
    """Verify data integrity using checksum"""
    return calculate_checksum(data) == expected_checksum
