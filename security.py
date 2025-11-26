"""
Security utilities: validation, threat detection, logging
"""
import re
from pathlib import Path
from typing import List, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models import AuditLog, LoginAttempt
from config import (
    MAX_FILENAME_LENGTH, MAX_FILE_SIZE, MAX_DESCRIPTION_LENGTH,
    ALLOWED_EXTENSIONS, DANGEROUS_EXTENSIONS, BLACKLISTED_HASHES,
    SUSPICIOUS_KEYWORDS, MAX_LOGIN_ATTEMPTS, LOGIN_ATTEMPT_WINDOW,
    SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL
)


def validate_filename(filename: str) -> Tuple[bool, str]:
    """Validate filename length and characters"""
    if len(filename) > MAX_FILENAME_LENGTH:
        return False, f"Filename too long (max {MAX_FILENAME_LENGTH} characters)"
    
    # Check for directory traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename:
        return False, "Invalid filename: directory traversal detected"
    
    # Check for null bytes
    if '\x00' in filename:
        return False, "Invalid filename: null byte detected"
    
    return True, "OK"


def validate_file_size(size: int) -> Tuple[bool, str]:
    """Validate file size"""
    if size > MAX_FILE_SIZE:
        return False, f"File too large (max {MAX_FILE_SIZE / (1024*1024):.0f} MB)"
    
    if size <= 0:
        return False, "Invalid file size"
    
    return True, "OK"


def validate_file_extension(filename: str) -> Tuple[bool, str]:
    """Validate file extension against whitelist and blacklist"""
    ext = Path(filename).suffix.lower()
    
    if ext in DANGEROUS_EXTENSIONS:
        return False, f"Dangerous file type blocked: {ext}"
    
    if ALLOWED_EXTENSIONS and ext not in ALLOWED_EXTENSIONS:
        return False, f"File type not allowed: {ext}"
    
    return True, "OK"


def validate_text_input(text: str, max_length: int = MAX_DESCRIPTION_LENGTH) -> Tuple[bool, str]:
    """Validate text input for buffer overflow protection"""
    if len(text) > max_length:
        return False, f"Input too long (max {max_length} characters)"
    
    # Check for null bytes
    if '\x00' in text:
        return False, "Invalid input: null byte detected"
    
    return True, "OK"


def check_malicious_hash(file_hash: str) -> bool:
    """Check if file hash is in blacklist"""
    return file_hash.lower() in BLACKLISTED_HASHES


def check_suspicious_content(content: bytes, filename: str) -> List[str]:
    """Check for suspicious keywords in file content"""
    findings = []
    
    # Only check text-based files
    text_extensions = {'.txt', '.sh', '.bat', '.ps1', '.py', '.js', '.cmd', '.vbs'}
    ext = Path(filename).suffix.lower()
    
    if ext not in text_extensions:
        return findings
    
    try:
        # Try to decode as text
        text_content = content.decode('utf-8', errors='ignore').lower()
        
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in text_content:
                findings.append(f"Suspicious keyword detected: {keyword}")
    except:
        # Not a text file, skip
        pass
    
    return findings


def log_event(
    db: Session,
    action: str,
    details: str = None,
    user_id: int = None,
    severity: str = SEVERITY_INFO,
    success: bool = True,
    ip_address: str = None
):
    """Log an event to the audit log"""
    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        severity=severity,
        success=success,
        ip_address=ip_address,
        timestamp=datetime.utcnow()
    )
    db.add(log_entry)
    db.commit()


def record_login_attempt(db: Session, username: str, success: bool, ip_address: str = None):
    """Record a login attempt"""
    attempt = LoginAttempt(
        username=username,
        success=success,
        ip_address=ip_address,
        timestamp=datetime.utcnow()
    )
    db.add(attempt)
    db.commit()


def check_brute_force(db: Session, username: str, ip_address: str = None) -> Tuple[bool, int]:
    """Check for brute force attempts
    Returns: (is_blocked, failed_attempts_count)
    """
    cutoff_time = datetime.utcnow() - timedelta(seconds=LOGIN_ATTEMPT_WINDOW)
    
    # Count failed attempts in the time window
    query = db.query(LoginAttempt).filter(
        LoginAttempt.username == username,
        LoginAttempt.success == False,
        LoginAttempt.timestamp >= cutoff_time
    )
    
    if ip_address:
        query = query.filter(LoginAttempt.ip_address == ip_address)
    
    failed_attempts = query.count()
    
    is_blocked = failed_attempts >= MAX_LOGIN_ATTEMPTS
    
    return is_blocked, failed_attempts


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent security issues"""
    # Remove any path components
    filename = Path(filename).name
    
    # Remove or replace problematic characters
    filename = re.sub(r'[^\w\s\-\.]', '_', filename)
    
    # Limit length
    if len(filename) > MAX_FILENAME_LENGTH:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_length = MAX_FILENAME_LENGTH - len(ext) - 1
        filename = name[:max_name_length] + '.' + ext if ext else name[:MAX_FILENAME_LENGTH]
    
    return filename
