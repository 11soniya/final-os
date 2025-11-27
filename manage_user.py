#!/usr/bin/env python3
"""
User management utility - disable 2FA, reset password, etc.
"""
from database import SessionLocal
from models import User
from auth import hash_password
import sys

def disable_2fa(username):
    """Disable 2FA for a user"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            print(f"❌ User '{username}' not found")
            return False
        
        if not user.two_factor_enabled:
            print(f"ℹ️  2FA is already disabled for '{username}'")
            return True
        
        user.two_factor_enabled = False
        user.two_factor_secret = None
        db.commit()
        
        print(f"✅ 2FA disabled for user '{username}'")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def reset_password(username, new_password):
    """Reset password for a user"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            print(f"❌ User '{username}' not found")
            return False
        
        if len(new_password) < 8:
            print("❌ Password must be at least 8 characters")
            return False
        
        user.password_hash = hash_password(new_password)
        db.commit()
        
        print(f"✅ Password reset for user '{username}'")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def enable_user(username):
    """Enable a disabled user account"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            print(f"❌ User '{username}' not found")
            return False
        
        if user.is_active:
            print(f"ℹ️  User '{username}' is already active")
            return True
        
        user.is_active = True
        db.commit()
        
        print(f"✅ User '{username}' enabled")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def disable_user(username):
    """Disable a user account"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            print(f"❌ User '{username}' not found")
            return False
        
        if not user.is_active:
            print(f"ℹ️  User '{username}' is already disabled")
            return True
        
        user.is_active = False
        db.commit()
        
        print(f"✅ User '{username}' disabled")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
        return False
    finally:
        db.close()

def list_users():
    """List all users"""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        
        print("=" * 80)
        print(f"{'Username':<20} {'Email':<30} {'Role':<10} {'2FA':<5} {'Active':<7}")
        print("=" * 80)
        
        for user in users:
            print(f"{user.username:<20} {user.email:<30} {user.role:<10} "
                  f"{'Yes' if user.two_factor_enabled else 'No':<5} "
                  f"{'Yes' if user.is_active else 'No':<7}")
        
        print("=" * 80)
        print(f"Total users: {len(users)}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        db.close()

def show_help():
    """Show help message"""
    print("""
User Management Utility
=======================

Usage:
    python manage_user.py [command] [arguments]

Commands:
    list                          - List all users
    disable-2fa <username>        - Disable 2FA for a user
    reset-password <username>     - Reset password for a user (interactive)
    enable <username>             - Enable a disabled user account
    disable <username>            - Disable a user account
    help                          - Show this help message

Examples:
    python manage_user.py list
    python manage_user.py disable-2fa john
    python manage_user.py reset-password john
    python manage_user.py enable john
    """)

def main():
    """Main function"""
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == 'list':
        list_users()
    
    elif command == 'disable-2fa':
        if len(sys.argv) < 3:
            print("❌ Usage: python manage_user.py disable-2fa <username>")
            return
        username = sys.argv[2]
        disable_2fa(username)
    
    elif command == 'reset-password':
        if len(sys.argv) < 3:
            print("❌ Usage: python manage_user.py reset-password <username>")
            return
        username = sys.argv[2]
        new_password = input("Enter new password: ").strip()
        confirm_password = input("Confirm new password: ").strip()
        
        if new_password != confirm_password:
            print("❌ Passwords do not match")
            return
        
        reset_password(username, new_password)
    
    elif command == 'enable':
        if len(sys.argv) < 3:
            print("❌ Usage: python manage_user.py enable <username>")
            return
        username = sys.argv[2]
        enable_user(username)
    
    elif command == 'disable':
        if len(sys.argv) < 3:
            print("❌ Usage: python manage_user.py disable <username>")
            return
        username = sys.argv[2]
        disable_user(username)
    
    elif command in ['help', '-h', '--help']:
        show_help()
    
    else:
        print(f"❌ Unknown command: {command}")
        show_help()

if __name__ == "__main__":
    main()
