"""
Pydantic schemas for request/response validation
"""
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime


# User schemas
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    
    @validator('password')
    def password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserLogin(BaseModel):
    username: str
    password: str
    otp: Optional[str] = None


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    two_factor_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    requires_2fa: bool = False


class TwoFactorSetup(BaseModel):
    secret: str
    qr_code: str
    uri: str


class TwoFactorVerify(BaseModel):
    token: str


# File schemas
class FileUpload(BaseModel):
    filename: str
    size: int
    content_type: Optional[str] = None


class FileResponse(BaseModel):
    id: int
    filename: str
    original_filename: str
    size: int
    checksum: str
    content_type: Optional[str]
    owner_id: int
    uploaded_at: datetime
    last_accessed: Optional[datetime]
    last_modified: datetime
    
    class Config:
        from_attributes = True


class FileShare(BaseModel):
    username: str
    can_read: bool = True
    can_write: bool = False
    can_share: bool = False


class FilePermissionResponse(BaseModel):
    id: int
    file_id: int
    user_id: int
    can_read: bool
    can_write: bool
    can_share: bool
    granted_at: datetime
    
    class Config:
        from_attributes = True


class FileListResponse(BaseModel):
    id: int
    filename: str
    size: int
    owner_id: int
    uploaded_at: datetime
    can_read: bool = False
    can_write: bool = False
    can_share: bool = False
    is_owner: bool = False


# Log schemas
class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    details: Optional[str]
    severity: str
    ip_address: Optional[str]
    timestamp: datetime
    success: bool
    
    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_users: int
    total_files: int
    total_logs: int
    recent_alerts: List[AuditLogResponse]
    login_stats: dict
    file_stats: dict
