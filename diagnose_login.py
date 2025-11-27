#!/usr/bin/env python3
"""
Diagnose login issues
"""
from database import SessionLocal
from models import User, LoginAttempt
from auth import verify_password
from datetime import datetime, timedelta
from config import MAX_LOGIN_ATTEMPTS, LOGIN_ATTEMPT_WINDOW

def diagnose_user(username):
    """Diagnose login issues for a user"""
    db = SessionLocal()
    try:
        print("=" * 70)
        print(f"   DIAGNOSIS FOR USER: {username}")
        print("=" * 70)
        print()
        
        # 1. Check if user exists
        print("1. USER EXISTENCE CHECK")
        print("-" * 70)
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            print(f"❌ User '{username}' NOT FOUND in database")
            print()
            print("Available users:")
            all_users = db.query(User).all()
            for u in all_users:
                print(f"  - {u.username} ({u.email})")
            return
        
        print(f"✅ User found: {username}")
        print(f"   Email: {user.email}")
        print(f"   Role: {user.role}")
        print(f"   Active: {'Yes' if user.is_active else 'No'}")
        print(f"   2FA Enabled: {'Yes' if user.two_factor_enabled else 'No'}")
        print(f"   Created: {user.created_at}")
        print(f"   Last Login: {user.last_login or 'Never'}")
        print(f"   Password hash: {user.password_hash[:60]}...")
        print()
        
        # 2. Check account status
        print("2. ACCOUNT STATUS CHECK")
        print("-" * 70)
        if not user.is_active:
            print(f"❌ Account is DISABLED")
        else:
            print(f"✅ Account is ACTIVE")
        print()
        
        # 3. Check brute force protection
        print("3. BRUTE FORCE PROTECTION CHECK")
        print("-" * 70)
        cutoff_time = datetime.utcnow() - timedelta(seconds=LOGIN_ATTEMPT_WINDOW)
        
        recent_attempts = db.query(LoginAttempt).filter(
            LoginAttempt.username == username,
            LoginAttempt.timestamp >= cutoff_time
        ).order_by(LoginAttempt.timestamp.desc()).all()
        
        failed_attempts = [a for a in recent_attempts if not a.success]
        successful_attempts = [a for a in recent_attempts if a.success]
        
        print(f"Time window: Last {LOGIN_ATTEMPT_WINDOW} seconds ({LOGIN_ATTEMPT_WINDOW//60} minutes)")
        print(f"Total recent attempts: {len(recent_attempts)}")
        print(f"Failed attempts: {len(failed_attempts)}")
        print(f"Successful attempts: {len(successful_attempts)}")
        print()
        
        if len(failed_attempts) >= MAX_LOGIN_ATTEMPTS:
            print(f"❌ ACCOUNT IS BLOCKED due to too many failed attempts!")
            print(f"   Threshold: {MAX_LOGIN_ATTEMPTS} failed attempts")
            print(f"   Current: {len(failed_attempts)} failed attempts")
            print()
            print("   Recent failed attempts:")
            for attempt in failed_attempts[:5]:
                print(f"   - {attempt.timestamp} from {attempt.ip_address or 'unknown IP'}")
            print()
            print(f"   To unblock, wait {LOGIN_ATTEMPT_WINDOW//60} minutes or clear failed attempts")
        else:
            print(f"✅ Account NOT blocked")
            print(f"   Failed attempts: {len(failed_attempts)}/{MAX_LOGIN_ATTEMPTS}")
        print()
        
        # 4. Show recent login history
        print("4. RECENT LOGIN HISTORY (last 10 attempts)")
        print("-" * 70)
        all_recent = db.query(LoginAttempt).filter(
            LoginAttempt.username == username
        ).order_by(LoginAttempt.timestamp.desc()).limit(10).all()
        
        if not all_recent:
            print("   No login attempts recorded")
        else:
            for attempt in all_recent:
                status = "✅ SUCCESS" if attempt.success else "❌ FAILED"
                print(f"   {attempt.timestamp} - {status} from {attempt.ip_address or 'unknown'}")
        print()
        
        # 5. Password hash verification test
        print("5. PASSWORD HASH FORMAT CHECK")
        print("-" * 70)
        if user.password_hash.startswith('$2b$'):
            print(f"✅ Password hash format is correct (bcrypt)")
            print(f"   Hash rounds: {user.password_hash.split('$')[2]}")
        else:
            print(f"❌ Invalid password hash format!")
            print(f"   Expected: $2b$... (bcrypt)")
            print(f"   Got: {user.password_hash[:20]}...")
        print()
        
        print("=" * 70)
        print("   DIAGNOSIS COMPLETE")
        print("=" * 70)
        print()
        
        # Offer to clear failed attempts
        if len(failed_attempts) > 0:
            clear = input("Would you like to clear failed login attempts? (y/n): ").strip().lower()
            if clear == 'y':
                for attempt in failed_attempts:
                    db.delete(attempt)
                db.commit()
                print(f"✅ Cleared {len(failed_attempts)} failed attempts")
        
    except Exception as e:
        print(f"❌ Error during diagnosis: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("Enter username to diagnose: ").strip()
    
    diagnose_user(username)
