#!/usr/bin/env python3
"""
Create an admin user for the Secure File Management System
Usage: python create_admin.py
"""

from database import SessionLocal, init_db
from models import User
from auth import hash_password
from config import ROLE_ADMIN

def create_admin():
    """Create an admin user interactively"""
    print("=" * 50)
    print("   Create Admin User")
    print("=" * 50)
    print()
    
    # Initialize database
    init_db()
    db = SessionLocal()
    
    try:
        # Get user input
        username = input("Enter admin username: ").strip()
        email = input("Enter admin email: ").strip()
        password = input("Enter admin password: ").strip()
        
        # Validate input
        if not username or not email or not password:
            print("\n❌ Error: All fields are required")
            return
        
        if len(password) < 8:
            print("\n❌ Error: Password must be at least 8 characters")
            return
        
        # Check if user exists
        existing = db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing:
            print(f"\n❌ Error: User with username '{username}' or email '{email}' already exists")
            
            # Offer to upgrade existing user to admin
            if existing.username == username:
                upgrade = input(f"\nWould you like to upgrade '{username}' to admin? (y/n): ").strip().lower()
                if upgrade == 'y':
                    existing.role = ROLE_ADMIN
                    db.commit()
                    print(f"\n✅ User '{username}' upgraded to admin successfully!")
            return
        
        # Create admin user
        admin = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role=ROLE_ADMIN,
            is_active=True
        )
        
        db.add(admin)
        db.commit()
        
        print(f"\n✅ Admin user '{username}' created successfully!")
        print(f"\nYou can now login at: http://localhost:8000/login")
        print(f"Username: {username}")
        print(f"Role: {ROLE_ADMIN}")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()
