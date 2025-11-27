# Troubleshooting Login Issues

## Problem: "Invalid username or password" error after some time

### Common Causes and Solutions:

#### 1. **2FA (Two-Factor Authentication) is Enabled**

**Symptom:** You can't login even though you're sure your password is correct.

**Cause:** If you enabled 2FA, you need to enter the 6-digit code from your authenticator app (like Google Authenticator or Authy) when logging in.

**Solution:**
1. Enter your username and password
2. Click "Login"
3. A 2FA code field will appear
4. Open your authenticator app and enter the 6-digit code
5. Click "Login" again

**If you lost access to your authenticator app:**
```bash
# Disable 2FA for a user
python manage_user.py disable-2fa <username>
```

#### 2. **Too Many Failed Login Attempts (Brute Force Protection)**

**Symptom:** You get "Too many failed login attempts" error.

**Cause:** The system blocks login attempts after 5 failed tries within 5 minutes.

**Solution:**
1. Wait 5 minutes for the lockout to expire
2. Or run the diagnostic tool to clear failed attempts:
```bash
python diagnose_login.py <username>
# Answer 'y' when asked to clear failed attempts
```

#### 3. **Account is Disabled**

**Symptom:** Login fails even with correct credentials.

**Cause:** An administrator may have disabled your account.

**Solution:**
```bash
# Enable a user account
python manage_user.py enable <username>
```

#### 4. **Password Was Changed**

**Symptom:** Your old password no longer works.

**Solution:**
```bash
# Reset password for a user
python manage_user.py reset-password <username>
```

## Diagnostic Tools

### Check User Status
```bash
python diagnose_login.py <username>
```
This will show:
- If the user exists
- Account status (active/disabled)
- 2FA status
- Recent login attempts
- Brute force protection status

### List All Users
```bash
python manage_user.py list
```

### Test Password
```bash
python test_password.py
```
Enter username and password to verify if password hashing is working correctly.

## User Management Commands

```bash
# List all users
python manage_user.py list

# Disable 2FA
python manage_user.py disable-2fa <username>

# Reset password
python manage_user.py reset-password <username>

# Enable user account
python manage_user.py enable <username>

# Disable user account
python manage_user.py disable <username>
```

## Prevention Tips

1. **Save Your 2FA Backup Codes:** When setting up 2FA, save the secret key or QR code
2. **Use Strong Passwords:** But write them down securely or use a password manager
3. **Avoid Multiple Failed Attempts:** The system locks you out after 5 failed tries
4. **Keep Your Environment Variables Consistent:** If using custom SECRET_KEY or ENCRYPTION_KEY, keep them the same

## Technical Notes

### Why Passwords Still Work After Restart

The system uses **bcrypt** for password hashing, which stores the salt in the hash itself. This means:
- Passwords remain valid after restart
- Each password has a unique salt
- No need to store salts separately

### Database Persistence

The application uses SQLite (or your configured database) which persists data to disk:
- Database file: `filemanager.db`
- Users, files, and settings are preserved between restarts
- As long as the database file exists, your data is safe

### Secret Keys

The `SECRET_KEY` in `config.py` is used for JWT tokens, not passwords:
- If SECRET_KEY changes, existing JWT tokens become invalid
- Users need to log in again to get new tokens
- But passwords still work (they use bcrypt, not SECRET_KEY)

### Encryption Key

The `ENCRYPTION_KEY` is used for file encryption:
- **CRITICAL:** Do not change this or you can't decrypt existing files
- Store it securely (use environment variable in production)
- If lost, encrypted files cannot be recovered
