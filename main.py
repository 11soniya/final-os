"""
Main FastAPI application for Secure File Management System
"""
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File as FastAPIFile, Form, Request
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
import os
from pathlib import Path
from datetime import datetime, timedelta
import secrets

from database import get_db, init_db
from models import User, File, FilePermission, AuditLog, LoginAttempt
from schemas import (
    UserCreate, UserLogin, UserResponse, TokenResponse,
    TwoFactorSetup, TwoFactorVerify, FileResponse, FileShare,
    FileListResponse, AuditLogResponse, DashboardStats, FilePermissionResponse
)
from auth import (
    hash_password, verify_password, create_access_token, decode_access_token,
    generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp
)
from encryption import encrypt_file, decrypt_file, calculate_checksum
from security import (
    validate_filename, validate_file_size, validate_file_extension,
    validate_text_input, check_malicious_hash, check_suspicious_content,
    log_event, record_login_attempt, check_brute_force, sanitize_filename
)
from config import (
    UPLOAD_FOLDER, MAX_FILE_SIZE, ROLE_ADMIN, ROLE_USER,
    SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL
)

# Initialize FastAPI app
app = FastAPI(
    title="Secure File Management System",
    description="A secure file management system with authentication, encryption, and threat detection",
    version="1.0.0"
)

# Setup templates
templates = Jinja2Templates(directory="templates")

# Security
security = HTTPBearer()

# Initialize database on startup
@app.on_event("startup")
def startup_event():
    init_db()
    print("Database initialized successfully")


# Dependency to get current user from token
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Extract and verify user from JWT token"""
    token = credentials.credentials
    payload = decode_access_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role"""
    if current_user.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


def check_file_permission(
    file_id: int,
    user: User,
    db: Session,
    require_read: bool = False,
    require_write: bool = False,
    require_share: bool = False
) -> File:
    """Check if user has permission to access a file"""
    file = db.query(File).filter(File.id == file_id, File.is_deleted == False).first()
    
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Owner has all permissions
    if file.owner_id == user.id:
        return file
    
    # Check explicit permissions
    permission = db.query(FilePermission).filter(
        FilePermission.file_id == file_id,
        FilePermission.user_id == user.id
    ).first()
    
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    if require_read and not permission.can_read:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Read permission denied"
        )
    
    if require_write and not permission.can_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission denied"
        )
    
    if require_share and not permission.can_share:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Share permission denied"
        )
    
    return file


# ============= AUTHENTICATION ROUTES =============

@app.post("/api/auth/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if username or email exists
    existing = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing:
        log_event(db, "registration_failed", f"Username/email already exists: {user_data.username}", 
                 severity=SEVERITY_WARNING, success=False)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Create new user
    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hash_password(user_data.password),
        role=ROLE_USER
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    log_event(db, "user_registered", f"New user registered: {user.username}", 
             user_id=user.id, severity=SEVERITY_INFO)
    
    return user


@app.post("/api/auth/login", response_model=TokenResponse)
def login(login_data: UserLogin, request: Request, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token"""
    ip_address = request.client.host if request.client else None
    
    # Check for brute force attempts
    is_blocked, failed_count = check_brute_force(db, login_data.username, ip_address)
    
    if is_blocked:
        log_event(db, "login_blocked", 
                 f"Login blocked due to too many failed attempts: {login_data.username}",
                 severity=SEVERITY_CRITICAL, success=False, ip_address=ip_address)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Please try again later."
        )
    
    # Find user
    user = db.query(User).filter(User.username == login_data.username).first()
    
    if not user or not verify_password(login_data.password, user.password_hash):
        record_login_attempt(db, login_data.username, False, ip_address)
        log_event(db, "login_failed", f"Invalid credentials: {login_data.username}",
                 severity=SEVERITY_WARNING, success=False, ip_address=ip_address)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )
    
    # Check 2FA
    if user.two_factor_enabled:
        if not login_data.otp:
            # Return response indicating 2FA is required
            return TokenResponse(
                access_token="",
                user=UserResponse.from_orm(user),
                requires_2fa=True
            )
        
        if not verify_totp(user.two_factor_secret, login_data.otp):
            record_login_attempt(db, login_data.username, False, ip_address)
            log_event(db, "2fa_failed", f"Invalid 2FA code: {user.username}",
                     user_id=user.id, severity=SEVERITY_WARNING, success=False, ip_address=ip_address)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA code"
            )
    
    # Create token
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    record_login_attempt(db, login_data.username, True, ip_address)
    log_event(db, "login_success", f"User logged in: {user.username}",
             user_id=user.id, severity=SEVERITY_INFO, ip_address=ip_address)
    
    return TokenResponse(
        access_token=access_token,
        user=UserResponse.from_orm(user),
        requires_2fa=False
    )


@app.post("/api/auth/2fa/setup", response_model=TwoFactorSetup)
def setup_2fa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Setup 2FA for current user"""
    secret = generate_totp_secret()
    uri = get_totp_uri(current_user.username, secret)
    qr_code = generate_qr_code(uri)
    
    # Store secret temporarily (will be confirmed on verification)
    current_user.two_factor_secret = secret
    db.commit()
    
    log_event(db, "2fa_setup_initiated", f"User initiated 2FA setup: {current_user.username}",
             user_id=current_user.id, severity=SEVERITY_INFO)
    
    return TwoFactorSetup(secret=secret, qr_code=qr_code, uri=uri)


@app.post("/api/auth/2fa/verify")
def verify_2fa(
    verify_data: TwoFactorVerify,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verify and enable 2FA"""
    if not current_user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA setup not initiated"
        )
    
    if not verify_totp(current_user.two_factor_secret, verify_data.token):
        log_event(db, "2fa_verification_failed", f"Invalid 2FA verification: {current_user.username}",
                 user_id=current_user.id, severity=SEVERITY_WARNING, success=False)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
    
    current_user.two_factor_enabled = True
    db.commit()
    
    log_event(db, "2fa_enabled", f"User enabled 2FA: {current_user.username}",
             user_id=current_user.id, severity=SEVERITY_INFO)
    
    return {"message": "2FA enabled successfully"}


@app.post("/api/auth/2fa/disable")
def disable_2fa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Disable 2FA for current user"""
    current_user.two_factor_enabled = False
    current_user.two_factor_secret = None
    db.commit()
    
    log_event(db, "2fa_disabled", f"User disabled 2FA: {current_user.username}",
             user_id=current_user.id, severity=SEVERITY_INFO)
    
    return {"message": "2FA disabled successfully"}


# ============= FILE MANAGEMENT ROUTES =============

@app.post("/api/files/upload", response_model=FileResponse)
async def upload_file(
    file: UploadFile = FastAPIFile(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    """Upload and encrypt a file"""
    ip_address = request.client.host if request and request.client else None
    
    # Validate filename
    valid, msg = validate_filename(file.filename)
    if not valid:
        log_event(db, "upload_blocked", f"Invalid filename: {file.filename} - {msg}",
                 user_id=current_user.id, severity=SEVERITY_WARNING, success=False, ip_address=ip_address)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    
    # Validate extension
    valid, msg = validate_file_extension(file.filename)
    if not valid:
        log_event(db, "upload_blocked", f"Dangerous file type: {file.filename}",
                 user_id=current_user.id, severity=SEVERITY_CRITICAL, success=False, ip_address=ip_address)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    
    # Read file content
    content = await file.read()
    
    # Validate size
    valid, msg = validate_file_size(len(content))
    if not valid:
        log_event(db, "upload_blocked", f"File too large: {file.filename}",
                 user_id=current_user.id, severity=SEVERITY_WARNING, success=False, ip_address=ip_address)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    
    # Calculate checksum
    checksum = calculate_checksum(content)
    
    # Check malicious hash
    if check_malicious_hash(checksum):
        log_event(db, "malware_detected", f"Blacklisted file hash detected: {file.filename}",
                 user_id=current_user.id, severity=SEVERITY_CRITICAL, success=False, ip_address=ip_address)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File blocked: matches known malware signature"
        )
    
    # Check suspicious content
    suspicious = check_suspicious_content(content, file.filename)
    if suspicious:
        log_event(db, "suspicious_content", 
                 f"Suspicious content in {file.filename}: {', '.join(suspicious)}",
                 user_id=current_user.id, severity=SEVERITY_CRITICAL, success=False, ip_address=ip_address)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File blocked: {', '.join(suspicious)}"
        )
    
    # Encrypt file
    encrypted_content = encrypt_file(content)
    
    # Generate unique filename
    sanitized_name = sanitize_filename(file.filename)
    unique_filename = f"{secrets.token_hex(16)}_{sanitized_name}"
    filepath = UPLOAD_FOLDER / unique_filename
    
    # Save encrypted file
    with open(filepath, 'wb') as f:
        f.write(encrypted_content)
    
    # Create database record
    db_file = File(
        filename=sanitized_name,
        original_filename=file.filename,
        filepath=str(filepath),
        size=len(content),
        checksum=checksum,
        content_type=file.content_type,
        encrypted=True,
        owner_id=current_user.id
    )
    
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    
    log_event(db, "file_uploaded", f"File uploaded: {file.filename} (ID: {db_file.id})",
             user_id=current_user.id, severity=SEVERITY_INFO, ip_address=ip_address)
    
    return db_file


@app.get("/api/files", response_model=List[FileListResponse])
def list_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all files accessible to current user"""
    # Get owned files
    owned_files = db.query(File).filter(
        File.owner_id == current_user.id,
        File.is_deleted == False
    ).all()
    
    # Get files with permissions
    permissions = db.query(FilePermission).filter(
        FilePermission.user_id == current_user.id
    ).all()
    
    shared_file_ids = [p.file_id for p in permissions]
    shared_files = db.query(File).filter(
        File.id.in_(shared_file_ids),
        File.is_deleted == False
    ).all() if shared_file_ids else []
    
    # Build response
    result = []
    
    for file in owned_files:
        result.append(FileListResponse(
            id=file.id,
            filename=file.filename,
            size=file.size,
            owner_id=file.owner_id,
            uploaded_at=file.uploaded_at,
            can_read=True,
            can_write=True,
            can_share=True,
            is_owner=True
        ))
    
    for file in shared_files:
        perm = next(p for p in permissions if p.file_id == file.id)
        result.append(FileListResponse(
            id=file.id,
            filename=file.filename,
            size=file.size,
            owner_id=file.owner_id,
            uploaded_at=file.uploaded_at,
            can_read=perm.can_read,
            can_write=perm.can_write,
            can_share=perm.can_share,
            is_owner=False
        ))
    
    return result


@app.get("/api/files/{file_id}", response_model=FileResponse)
def get_file_metadata(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get file metadata"""
    file = check_file_permission(file_id, current_user, db, require_read=True)
    
    # Update last accessed
    file.last_accessed = datetime.utcnow()
    db.commit()
    
    return file


@app.get("/api/files/{file_id}/download")
async def download_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    """Download and decrypt a file"""
    ip_address = request.client.host if request and request.client else None
    
    file = check_file_permission(file_id, current_user, db, require_read=True)
    
    # Read encrypted file
    if not os.path.exists(file.filepath):
        log_event(db, "download_failed", f"File not found on disk: {file.filename}",
                 user_id=current_user.id, severity=SEVERITY_CRITICAL, success=False, ip_address=ip_address)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found on disk"
        )
    
    with open(file.filepath, 'rb') as f:
        encrypted_content = f.read()
    
    # Decrypt file
    try:
        decrypted_content = decrypt_file(encrypted_content)
    except Exception as e:
        log_event(db, "decryption_failed", f"Failed to decrypt file {file.filename}: {str(e)}",
                 user_id=current_user.id, severity=SEVERITY_CRITICAL, success=False, ip_address=ip_address)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt file"
        )
    
    # Update last accessed
    file.last_accessed = datetime.utcnow()
    db.commit()
    
    log_event(db, "file_downloaded", f"File downloaded: {file.filename} (ID: {file_id})",
             user_id=current_user.id, severity=SEVERITY_INFO, ip_address=ip_address)
    
    # Return file
    return StreamingResponse(
        iter([decrypted_content]),
        media_type=file.content_type or 'application/octet-stream',
        headers={
            'Content-Disposition': f'attachment; filename="{file.filename}"'
        }
    )


@app.delete("/api/files/{file_id}")
def delete_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    """Delete a file (soft delete)"""
    ip_address = request.client.host if request and request.client else None
    
    file = db.query(File).filter(File.id == file_id, File.is_deleted == False).first()
    
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Only owner can delete
    if file.owner_id != current_user.id:
        log_event(db, "delete_denied", f"Unauthorized delete attempt: {file.filename}",
                 user_id=current_user.id, severity=SEVERITY_WARNING, success=False, ip_address=ip_address)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only file owner can delete"
        )
    
    # Soft delete
    file.is_deleted = True
    db.commit()
    
    log_event(db, "file_deleted", f"File deleted: {file.filename} (ID: {file_id})",
             user_id=current_user.id, severity=SEVERITY_INFO, ip_address=ip_address)
    
    return {"message": "File deleted successfully"}


@app.post("/api/files/{file_id}/share")
def share_file(
    file_id: int,
    share_data: FileShare,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    """Share a file with another user"""
    ip_address = request.client.host if request and request.client else None
    
    file = db.query(File).filter(File.id == file_id, File.is_deleted == False).first()
    
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Check if user has share permission
    if file.owner_id != current_user.id:
        # Check if user has share permission
        perm = db.query(FilePermission).filter(
            FilePermission.file_id == file_id,
            FilePermission.user_id == current_user.id,
            FilePermission.can_share == True
        ).first()
        
        if not perm:
            log_event(db, "share_denied", f"Unauthorized share attempt: {file.filename}",
                     user_id=current_user.id, severity=SEVERITY_WARNING, success=False, ip_address=ip_address)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to share this file"
            )
    
    # Check if target user exists
    target_user = db.query(User).filter(User.username == share_data.username).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{share_data.username}' not found"
        )
    
    # Prevent sharing with self
    if target_user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot share file with yourself"
        )
    
    # Check if permission already exists
    existing = db.query(FilePermission).filter(
        FilePermission.file_id == file_id,
        FilePermission.user_id == target_user.id
    ).first()
    
    if existing:
        # Update existing permission
        existing.can_read = share_data.can_read
        existing.can_write = share_data.can_write
        existing.can_share = share_data.can_share
        existing.granted_at = datetime.utcnow()
        existing.granted_by = current_user.id
    else:
        # Create new permission
        permission = FilePermission(
            file_id=file_id,
            user_id=target_user.id,
            can_read=share_data.can_read,
            can_write=share_data.can_write,
            can_share=share_data.can_share,
            granted_by=current_user.id
        )
        db.add(permission)
    
    db.commit()
    
    log_event(db, "file_shared", 
             f"File shared: {file.filename} with user {target_user.username}",
             user_id=current_user.id, severity=SEVERITY_INFO, ip_address=ip_address)
    
    return {"message": "File shared successfully"}


@app.get("/api/files/{file_id}/permissions", response_model=List[FilePermissionResponse])
def get_file_permissions(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all permissions for a file (owner only)"""
    file = db.query(File).filter(File.id == file_id, File.is_deleted == False).first()
    
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    if file.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only file owner can view permissions"
        )
    
    permissions = db.query(FilePermission).filter(
        FilePermission.file_id == file_id
    ).all()
    
    return permissions


@app.get("/api/users/search")
def search_users(
    query: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Search for users by username or email (for file sharing)"""
    if not query or len(query) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query must be at least 2 characters"
        )
    
    # Search by username or email
    users = db.query(User).filter(
        User.is_active == True,
        User.id != current_user.id,  # Exclude current user
        (User.username.ilike(f"%{query}%") | User.email.ilike(f"%{query}%"))
    ).limit(10).all()
    
    # Return only safe user info
    return [{
        "username": user.username,
        "email": user.email
    } for user in users]


# ============= ADMIN ROUTES =============

@app.get("/api/admin/users", response_model=List[UserResponse])
def list_users(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """List all users (admin only)"""
    users = db.query(User).all()
    return users


@app.get("/api/admin/logs", response_model=List[AuditLogResponse])
def get_logs(
    limit: int = 100,
    severity: Optional[str] = None,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get audit logs (admin only)"""
    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    
    if severity:
        query = query.filter(AuditLog.severity == severity)
    
    logs = query.limit(limit).all()
    return logs


@app.get("/api/admin/files")
def get_all_files_admin(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get all files with complete metadata (admin only)"""
    files = db.query(File).filter(File.is_deleted == False).order_by(File.uploaded_at.desc()).all()
    
    result = []
    for file in files:
        owner = db.query(User).filter(User.id == file.owner_id).first()
        result.append({
            "id": file.id,
            "filename": file.filename,
            "original_filename": file.original_filename,
            "size": file.size,
            "content_type": file.content_type,
            "checksum": file.checksum,
            "owner_id": file.owner_id,
            "owner_username": owner.username if owner else "Unknown",
            "uploaded_at": file.uploaded_at.isoformat(),
            "last_accessed": file.last_accessed.isoformat() if file.last_accessed else None,
            "last_modified": file.last_modified.isoformat(),
            "encrypted": file.encrypted
        })
    
    return result


@app.get("/api/admin/dashboard", response_model=DashboardStats)
def get_dashboard_stats(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics (admin only)"""
    total_users = db.query(User).count()
    total_files = db.query(File).filter(File.is_deleted == False).count()
    total_logs = db.query(AuditLog).count()
    
    # Recent alerts (WARNING or CRITICAL)
    recent_alerts = db.query(AuditLog).filter(
        AuditLog.severity.in_([SEVERITY_WARNING, SEVERITY_CRITICAL])
    ).order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    # Login stats (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    login_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.timestamp >= seven_days_ago
    ).all()
    
    login_stats = {
        "total": len(login_attempts),
        "successful": sum(1 for a in login_attempts if a.success),
        "failed": sum(1 for a in login_attempts if not a.success)
    }
    
    # File stats
    total_size = db.query(func.sum(File.size)).filter(File.is_deleted == False).scalar() or 0
    file_stats = {
        "total": total_files,
        "total_size": total_size
    }
    
    return DashboardStats(
        total_users=total_users,
        total_files=total_files,
        total_logs=total_logs,
        recent_alerts=[AuditLogResponse.from_orm(log) for log in recent_alerts],
        login_stats=login_stats,
        file_stats=file_stats
    )


# ============= WEB UI ROUTES =============

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page - redirect to login"""
    return RedirectResponse(url="/login")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page"""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Registration page"""
    return templates.TemplateResponse("register.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """User dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """Admin dashboard page"""
    return templates.TemplateResponse("admin.html", {"request": request})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
