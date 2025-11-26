# Quick Start Guide

## 🚀 Get Started in 3 Minutes

### Step 1: Setup (1 minute)

```bash
cd "/Users/rizwan/Desktop/file manager"
./setup.sh
```

This will:
- Create a virtual environment
- Install all dependencies
- Initialize the database
- Create necessary directories

### Step 2: Start the Server (30 seconds)

```bash
python3 main.py
```

Or with auto-reload for development:

```bash
uvicorn main:app --reload
```

### Step 3: Create Admin User (1 minute)

```bash
python3 create_admin.py
```

Follow the prompts to create your admin account.

### Step 4: Access the Application (30 seconds)

Open your browser:
- **Login**: http://localhost:8000/login
- **Register**: http://localhost:8000/register
- **API Docs**: http://localhost:8000/docs

---

## 🎯 Demo Workflow

### As a Regular User:

1. **Register** a new account (strong password required)
2. **Enable 2FA** from the dashboard
3. **Upload** a file (it gets encrypted automatically)
4. **Download** your file (it gets decrypted on-the-fly)
5. **Share** with another user (by user ID)
6. Try uploading a `.exe` file - it will be blocked!

### As an Admin:

1. Login with admin credentials
2. Go to **Admin Dashboard** at http://localhost:8000/admin
3. View:
   - Total users, files, and logs
   - Login success/failure statistics
   - Recent security alerts
   - Complete audit log
   - All registered users

---

## 🔒 Security Features to Test

### 1. Password Security
- Try weak password → Rejected
- Passwords are hashed (never stored plain)

### 2. Two-Factor Authentication
- Enable 2FA with Google Authenticator
- Login requires both password + OTP

### 3. File Encryption
- All uploaded files are encrypted at rest
- Check `uploads/` folder - files are unreadable
- Download works perfectly (automatic decryption)

### 4. Threat Detection
- Upload `.exe`, `.bat`, `.sh` → Blocked
- Upload file > 50MB → Rejected
- Multiple failed logins → Brute force detection

### 5. Access Control
- Users can only see their own files + shared files
- Only owners can delete files
- Sharing requires explicit permissions

### 6. Audit Logging
- All actions are logged
- Check Admin Dashboard for complete history
- Security alerts are highlighted

---


---

## 🐛 Common Issues

### "Module not found"
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "Port already in use"
```bash
uvicorn main:app --port 8001
```

### "Database locked"
```bash
rm filemanager.db
python3 main.py
```
