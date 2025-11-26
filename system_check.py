#!/usr/bin/env python3
"""
System check script for Secure File Management System
Verifies that all components are properly configured
"""

import sys
import os
from pathlib import Path

def print_status(message, status):
    """Print colored status message"""
    colors = {
        'ok': '\033[0;32m✓\033[0m',
        'fail': '\033[0;31m✗\033[0m',
        'warn': '\033[1;33m!\033[0m'
    }
    print(f"{colors.get(status, '?')} {message}")

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print_status(f"Python {version.major}.{version.minor}.{version.micro}", 'ok')
        return True
    else:
        print_status(f"Python {version.major}.{version.minor}.{version.micro} (requires 3.8+)", 'fail')
        return False

def check_dependencies():
    """Check if all required packages are installed"""
    required_packages = [
        'fastapi',
        'uvicorn',
        'sqlalchemy',
        'bcrypt',
        'cryptography',
        'pyotp',
        'pydantic',
        'jose',
        'jinja2',
        'qrcode',
        'passlib'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print_status(f"Package '{package}'", 'ok')
        except ImportError:
            print_status(f"Package '{package}'", 'fail')
            missing.append(package)
    
    return len(missing) == 0

def check_files():
    """Check if all required files exist"""
    required_files = [
        'main.py',
        'models.py',
        'database.py',
        'auth.py',
        'encryption.py',
        'security.py',
        'schemas.py',
        'config.py',
        'requirements.txt'
    ]
    
    required_dirs = [
        'templates',
        'uploads'
    ]
    
    required_templates = [
        'templates/base.html',
        'templates/login.html',
        'templates/register.html',
        'templates/dashboard.html',
        'templates/admin.html'
    ]
    
    all_ok = True
    
    for file in required_files:
        if os.path.exists(file):
            print_status(f"File '{file}'", 'ok')
        else:
            print_status(f"File '{file}'", 'fail')
            all_ok = False
    
    for dir in required_dirs:
        if os.path.exists(dir):
            print_status(f"Directory '{dir}/'", 'ok')
        else:
            print_status(f"Directory '{dir}/'", 'warn')
            if dir == 'uploads':
                os.makedirs(dir, exist_ok=True)
                print_status(f"Created directory '{dir}/'", 'ok')
    
    for template in required_templates:
        if os.path.exists(template):
            print_status(f"Template '{template}'", 'ok')
        else:
            print_status(f"Template '{template}'", 'fail')
            all_ok = False
    
    return all_ok

def check_config():
    """Check configuration"""
    try:
        import config
        print_status("Config module", 'ok')
        
        # Check important settings
        if config.SECRET_KEY == "your-secret-key-change-in-production":
            print_status("SECRET_KEY (default - change in production)", 'warn')
        else:
            print_status("SECRET_KEY (custom)", 'ok')
        
        if config.ENCRYPTION_KEY:
            print_status("ENCRYPTION_KEY (configured)", 'ok')
        else:
            print_status("ENCRYPTION_KEY (missing)", 'fail')
            return False
        
        print_status(f"Max file size: {config.MAX_FILE_SIZE / (1024*1024):.0f}MB", 'ok')
        print_status(f"Allowed extensions: {len(config.ALLOWED_EXTENSIONS)} types", 'ok')
        print_status(f"Dangerous extensions blocked: {len(config.DANGEROUS_EXTENSIONS)} types", 'ok')
        
        return True
    except Exception as e:
        print_status(f"Config check failed: {e}", 'fail')
        return False

def check_database():
    """Check database setup"""
    try:
        from database import init_db, engine
        print_status("Database module", 'ok')
        
        # Try to initialize database
        init_db()
        print_status("Database initialization", 'ok')
        
        # Check if tables exist
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        required_tables = ['users', 'files', 'file_permissions', 'logs', 'login_attempts']
        for table in required_tables:
            if table in tables:
                print_status(f"Table '{table}'", 'ok')
            else:
                print_status(f"Table '{table}'", 'fail')
                return False
        
        return True
    except Exception as e:
        print_status(f"Database check failed: {e}", 'fail')
        return False

def main():
    """Run all system checks"""
    print("=" * 60)
    print("   Secure File Management System - System Check")
    print("=" * 60)
    print()
    
    checks = [
        ("Python Version", check_python_version),
        ("Required Dependencies", check_dependencies),
        ("Project Files", check_files),
        ("Configuration", check_config),
        ("Database Setup", check_database)
    ]
    
    results = []
    
    for name, check_func in checks:
        print(f"\nChecking {name}...")
        print("-" * 60)
        result = check_func()
        results.append((name, result))
    
    print()
    print("=" * 60)
    print("   Summary")
    print("=" * 60)
    print()
    
    all_passed = True
    for name, result in results:
        status = 'PASS' if result else 'FAIL'
        color = '\033[0;32m' if result else '\033[0;31m'
        print(f"{color}{status}\033[0m - {name}")
        if not result:
            all_passed = False
    
    print()
    
    if all_passed:
        print("\033[0;32m✓ All checks passed! System is ready to run.\033[0m")
        print()
        print("Start the application with:")
        print("  python3 main.py")
        print()
        print("Or:")
        print("  uvicorn main:app --reload")
        print()
        return 0
    else:
        print("\033[0;31m✗ Some checks failed. Please fix the issues above.\033[0m")
        print()
        print("Try running:")
        print("  ./setup.sh")
        print()
        return 1

if __name__ == "__main__":
    sys.exit(main())
