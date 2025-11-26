# Secure File Management System

A comprehensive secure file management system with authentication, encryption, and threat detection built with FastAPI, demonstrating security best practices for file operations.

## 🔒 Security Features

### Module A: Authentication & Access Control
- **Password Security**: Bcrypt hashing with strong password requirements
- **Two-Factor Authentication (2FA)**: TOTP-based with Google Authenticator support
- **JWT Tokens**: Secure session management with expiration
- **Role-Based Access Control (RBAC)**: Admin and User roles
- **Per-File Permissions**: Granular read/write/share permissions
- **Brute Force Protection**: Login attempt limiting and monitoring

### Module B: Secure File Storage & Operations
- **Encryption at Rest**: AES-256 encryption for all uploaded files
- **Secure File Operations**: Upload, download, share, and delete with permission checks
- **File Metadata Management**: Track ownership, access times, and checksums
- **Integrity Verification**: SHA-256 checksums for file validation
- **Access Control**: Owner-based permissions with sharing capabilities

### Module C: Threat Detection & Monitoring
- **Input Validation**: Protection against buffer overflow-style attacks
- **Dangerous File Detection**: Blocking of executable and potentially harmful file types
- **Malware Indicators**: File hash blacklisting and suspicious content scanning
- **Audit Logging**: Comprehensive event logging with severity levels
- **Security Dashboard**: Real-time monitoring of security events and alerts
- **Login Monitoring**: Track failed attempts and detect brute force attacks

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Client (Browser)                       │
│              HTML/CSS/Bootstrap + JavaScript                 │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTPS
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                   FastAPI Application                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │     Auth     │  │    Files     │  │    Admin     │      │
│  │   Routes     │  │   Routes     │  │   Routes     │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│  ┌──────▼──────────────────▼──────────────────▼───────┐    │
│  │            Security & Validation Layer             │    │
│  │  (Input validation, threat detection, logging)     │    │
│  └──────┬──────────────────┬──────────────────┬───────┘    │
│         │                  │                  │              │
│  ┌──────▼───────┐   ┌──────▼───────┐   ┌────▼────┐        │
│  │     Auth     │   │  Encryption  │   │  Access │        │
│  │   Service    │   │   Service    │   │ Control │        │
│  └──────┬───────┘   └──────┬───────┘   └────┬────┘        │
└─────────┼──────────────────┼────────────────┼──────────────┘
          │                  │                 │
          ▼                  ▼                 ▼
┌─────────────────────────────────────────────────────────────┐
│                  SQLite Database                             │
│  ┌────────┐  ┌────────┐  ┌──────────────┐  ┌────────┐     │
│  │ Users  │  │ Files  │  │Permissions   │  │  Logs  │     │
│  └────────┘  └────────┘  └──────────────┘  └────────┘     │
└─────────────────────────────────────────────────────────────┘
          
          Encrypted Files stored in uploads/ directory
```

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

## 🚀 Installation & Setup

### 1. Clone or Navigate to Project Directory

```bash
cd "/Users/rizwan/Desktop/file manager"
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
```

### 3. Activate Virtual Environment

**On macOS/Linux:**
```bash
source venv/bin/activate
```

**On Windows:**
```bash
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure Environment Variables (Optional)

Create a `.env` file for production settings:

```bash
SECRET_KEY=your-secret-key-here-change-in-production
ENCRYPTION_KEY=your-32-byte-encryption-key-here
DATABASE_URL=sqlite:///filemanager.db
```

### 6. Initialize Database

The database will be automatically created on first run. To manually initialize:

```bash
python3 -c "from database import init_db; init_db(); print('Database initialized')"
```

### 7. Run the Application

```bash
python3 main.py
```

Or using uvicorn directly:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 8. Access the Application

Open your web browser and navigate to:
- **Application**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Alternative API Docs**: http://localhost:8000/redoc

## 👤 Creating the First Admin User

After starting the application, create your first user:

1. Go to http://localhost:8000/register
2. Register a new account
3. Stop the application
4. Update the user role in the database:

```bash
sqlite3 filemanager.db
UPDATE users SET role = 'ADMIN' WHERE username = 'your-username';
.quit
```

5. Restart the application

## 📖 Usage Guide

### User Registration & Login

1. **Register**: Create an account with a strong password
   - Password must contain: uppercase, lowercase, digit, special character
   - Minimum 8 characters

2. **Login**: Use your credentials to access the dashboard
   - Optionally enable 2FA for enhanced security

### Enabling Two-Factor Authentication

1. Login to your account
2. Click "2FA Settings" button
3. Click "Setup 2FA"
4. Scan the QR code with Google Authenticator or similar app
5. Enter the 6-digit code to verify and enable

### File Management

#### Upload Files
1. Click "Upload File" button
2. Select a file (max 50MB)
3. Allowed formats: PDF, DOCX, TXT, JPG, PNG, ZIP, CSV, XLSX
4. Files are automatically encrypted before storage

#### Download Files
1. Click the download icon next to any file you have read access to
2. File is decrypted on-the-fly and downloaded

#### Share Files
1. Click the share icon next to a file you own
2. Enter the user ID to share with
3. Select permissions: Read, Write, Share
4. Click "Share"

#### Delete Files
1. Only file owners can delete files
2. Click the delete (trash) icon
3. Confirm deletion

### Admin Dashboard

Admins have access to:
- **Statistics**: User count, file count, log count
- **Login Analytics**: Success/failure rates over last 7 days
- **Security Alerts**: Real-time warning and critical events
- **Audit Logs**: Complete system activity log with filtering
- **User Management**: View all registered users

## 🔐 Security Implementation Details

### Password Hashing
- Algorithm: Bcrypt (12 rounds)
- No plain text passwords stored
- Automatic password strength validation

### File Encryption
- Algorithm: Fernet (AES-128 CBC with HMAC)
- Unique encryption for each file
- Key stored securely (use environment variables in production)

### Access Control
```
File Owner → Full access (read, write, delete, share)
   ↓
Shared Users → Custom permissions (read, write, share)
   ↓
Others → No access
```

### Threat Detection

**Blocked File Types:**
- Executables: `.exe`, `.bat`, `.sh`, `.cmd`
- Scripts: `.js`, `.ps1`, `.vbs`
- Suspicious: `.jar`, `.msi`, `.com`

**Validation Checks:**
- Filename length (max 255 chars)
- File size (max 50MB)
- Directory traversal attempts
- Null byte injection
- Malicious file hashes
- Suspicious content patterns

### Audit Logging

All important events are logged:
- User registration/login
- File operations (upload, download, share, delete)
- Permission changes
- Security violations
- Failed authentication attempts

Log Severity Levels:
- **INFO**: Normal operations
- **WARNING**: Suspicious but not critical
- **CRITICAL**: Security violations, blocked attacks

## 📁 Project Structure

```
file manager/
├── main.py                 # FastAPI application and routes
├── config.py              # Configuration settings
├── database.py            # Database setup and session management
├── models.py              # SQLAlchemy database models
├── schemas.py             # Pydantic validation schemas
├── auth.py                # Authentication utilities (JWT, 2FA)
├── encryption.py          # File encryption/decryption
├── security.py            # Security validation and threat detection
├── requirements.txt       # Python dependencies
├── .gitignore            # Git ignore rules
├── README.md             # This file
├── prd.md                # Product requirements document
├── templates/            # HTML templates
│   ├── base.html         # Base template with navbar
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   ├── dashboard.html    # User file management dashboard
│   └── admin.html        # Admin security dashboard
└── uploads/              # Encrypted file storage (auto-created)
```

## 🧪 Testing

### Manual Testing Scenarios

1. **Authentication Testing**
   - Register with weak password (should fail)
   - Login with wrong credentials (should fail and log)
   - Enable 2FA and login with/without OTP
   - Attempt multiple failed logins (brute force detection)

2. **File Security Testing**
   - Upload dangerous file type (.exe, .bat) - should block
   - Upload oversized file - should reject
   - Try to download file without permission - should deny
   - Share file and verify permissions work correctly

3. **Access Control Testing**
   - Try to access admin dashboard as regular user
   - Try to delete another user's file
   - Share file and verify shared user can access
   - Revoke permissions and verify access removed

4. **Threat Detection Testing**
   - Upload file with suspicious content
   - Try filename with directory traversal (../)
   - Check audit logs for all events

## 🛡️ Security Best Practices Demonstrated

1. ✅ **Password Security**: Bcrypt hashing, strong requirements
2. ✅ **Multi-Factor Authentication**: TOTP-based 2FA
3. ✅ **Session Management**: JWT tokens with expiration
4. ✅ **Encryption at Rest**: AES encryption for all files
5. ✅ **Input Validation**: Comprehensive validation on all inputs
6. ✅ **Access Control**: RBAC and per-resource permissions
7. ✅ **Threat Detection**: File type blocking, malware checking
8. ✅ **Audit Logging**: Complete activity tracking
9. ✅ **Brute Force Protection**: Login attempt limiting
10. ✅ **Security Monitoring**: Real-time dashboard and alerts

## 🔧 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login and get JWT token
- `POST /api/auth/2fa/setup` - Setup 2FA
- `POST /api/auth/2fa/verify` - Verify and enable 2FA
- `POST /api/auth/2fa/disable` - Disable 2FA

### File Management
- `GET /api/files` - List accessible files
- `POST /api/files/upload` - Upload and encrypt file
- `GET /api/files/{id}` - Get file metadata
- `GET /api/files/{id}/download` - Download and decrypt file
- `DELETE /api/files/{id}` - Delete file (owner only)
- `POST /api/files/{id}/share` - Share file with user
- `GET /api/files/{id}/permissions` - Get file permissions

### Admin
- `GET /api/admin/users` - List all users
- `GET /api/admin/logs` - Get audit logs
- `GET /api/admin/dashboard` - Get dashboard statistics

## 🐛 Troubleshooting

### Database Locked Error
```bash
# Close all connections and restart
rm filemanager.db
python3 main.py
```

### Import Errors
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

### Port Already in Use
```bash
# Change port in main.py or run on different port
uvicorn main:app --port 8001
```

### File Upload Fails
- Check `uploads/` directory exists and has write permissions
- Verify file size is under 50MB
- Ensure file type is allowed



