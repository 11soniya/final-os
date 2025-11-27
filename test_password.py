#!/usr/bin/env python3
"""
Test password hashing and verification
"""
from database import SessionLocal
from models import User
from auth import hash_password, verify_password

def test_user_password(username, test_password):
    """Test if a password works for a user"""
    db = SessionLocal()
    try:
        # Find user
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            print(f"❌ User '{username}' not found in database")
            return False
        
        print(f"✓ User '{username}' found")
        print(f"  Email: {user.email}")
        print(f"  Active: {user.is_active}")
        print(f"  Role: {user.role}")
        print(f"  Password hash: {user.password_hash[:60]}...")
        print()
        
        # Test password
        print(f"Testing password verification...")
        is_valid = verify_password(test_password, user.password_hash)
        
        if is_valid:
            print(f"✅ Password verification SUCCESSFUL")
        else:
            print(f"❌ Password verification FAILED")
            
            # Try rehashing the password to see what it would look like
            print()
            print("Testing hash generation:")
            new_hash = hash_password(test_password)
            print(f"New hash would be: {new_hash[:60]}...")
            
            # Test if the new hash would work
            test_verify = verify_password(test_password, new_hash)
            print(f"New hash verification: {'✅ WORKS' if test_verify else '❌ FAILS'}")
        
        return is_valid
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    print("=" * 60)
    print("   Password Verification Test")
    print("=" * 60)
    print()
    
    # Get user input
    username = input("Enter username to test: ").strip()
    password = input("Enter password to test: ").strip()
    
    print()
    print("-" * 60)
    print()
    
    test_user_password(username, password)
