"""
Configuration settings for the secure file management system
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Encryption key for file storage (32 bytes for AES-256)
# In production, store this in a secure key management system
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "Wh8bQ7kR9mP2xV5nL3fT6jC4yN8aE1dS")

# Database
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'filemanager.db'}")

# File upload settings
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_FILENAME_LENGTH = 255
MAX_DESCRIPTION_LENGTH = 1000

# Allowed and blocked file extensions
ALLOWED_EXTENSIONS = {'.pdf', '.docx', '.doc', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.csv', '.xlsx', '.xls'}
DANGEROUS_EXTENSIONS = {'.exe', '.bat', '.sh', '.js', '.ps1', '.cmd', '.com', '.msi', '.vbs', '.jar'}

# Malware detection - sample blacklisted file hashes (SHA256)
# These are just examples for demonstration
BLACKLISTED_HASHES = {
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # Empty file hash (example)
    '5f4dcc3b5aa765d61d8327deb882cf99',  # Another example hash
}

# Suspicious keywords in files (simple malware detection)
SUSPICIOUS_KEYWORDS = [
    'rm -rf /',
    'format c:',
    'powershell -enc',
    'eval(base64',
    '__import__("os").system',
]

# Login security
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW = 300  # 5 minutes in seconds

# Roles
ROLE_ADMIN = "ADMIN"
ROLE_USER = "USER"

# Logging severity levels
SEVERITY_INFO = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_CRITICAL = "CRITICAL"
