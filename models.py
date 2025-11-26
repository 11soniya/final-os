"""
Database models for the secure file management system
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    """User model for authentication and access control"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="USER", nullable=False)  # USER or ADMIN
    two_factor_secret = Column(String(32), nullable=True)  # TOTP secret
    two_factor_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    owned_files = relationship("File", back_populates="owner", foreign_keys="File.owner_id")
    file_permissions = relationship("FilePermission", back_populates="user", foreign_keys="FilePermission.user_id")
    logs = relationship("AuditLog", back_populates="user")


class File(Base):
    """File model for storing file metadata"""
    __tablename__ = "files"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    filepath = Column(String(500), nullable=False)  # Encrypted file path
    size = Column(Integer, nullable=False)  # File size in bytes
    checksum = Column(String(64), nullable=False)  # SHA256 hash
    content_type = Column(String(100), nullable=True)
    encrypted = Column(Boolean, default=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    last_accessed = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, default=datetime.utcnow)
    is_deleted = Column(Boolean, default=False)
    
    # Relationships
    owner = relationship("User", back_populates="owned_files", foreign_keys=[owner_id])
    permissions = relationship("FilePermission", back_populates="file", cascade="all, delete-orphan")


class FilePermission(Base):
    """File permission model for access control"""
    __tablename__ = "file_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    can_read = Column(Boolean, default=False)
    can_write = Column(Boolean, default=False)
    can_share = Column(Boolean, default=False)
    granted_at = Column(DateTime, default=datetime.utcnow)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    file = relationship("File", back_populates="permissions")
    user = relationship("User", back_populates="file_permissions", foreign_keys=[user_id])


class AuditLog(Base):
    """Audit log model for security monitoring"""
    __tablename__ = "logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)  # login, upload, download, share, etc.
    details = Column(Text, nullable=True)  # Additional context
    severity = Column(String(20), default="INFO")  # INFO, WARNING, CRITICAL
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    success = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="logs")


class LoginAttempt(Base):
    """Track login attempts for brute-force detection"""
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
