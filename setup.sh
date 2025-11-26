#!/bin/bash

# Secure File Manager - Setup Script
# This script sets up the development environment

echo "================================================"
echo "   Secure File Management System - Setup"
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓${NC} Python 3 found: $PYTHON_VERSION"
else
    echo -e "${RED}✗${NC} Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓${NC} Virtual environment created"
else
    echo -e "${YELLOW}!${NC} Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate
echo -e "${GREEN}✓${NC} Virtual environment activated"

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1
echo -e "${GREEN}✓${NC} pip upgraded"

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} All dependencies installed successfully"
else
    echo -e "${RED}✗${NC} Failed to install dependencies"
    exit 1
fi

# Create necessary directories
echo ""
echo "Creating necessary directories..."
mkdir -p uploads
echo -e "${GREEN}✓${NC} uploads/ directory created"

# Initialize database
echo ""
echo "Initializing database..."
python3 << EOF
from database import init_db
try:
    init_db()
    print("${GREEN}✓${NC} Database initialized successfully")
except Exception as e:
    print(f"${RED}✗${NC} Failed to initialize database: {e}")
EOF

# Create first admin user (optional)
echo ""
echo "================================================"
echo "   Setup Complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Start the application:"
echo "   ${GREEN}python3 main.py${NC}"
echo ""
echo "2. Or use uvicorn:"
echo "   ${GREEN}uvicorn main:app --reload${NC}"
echo ""
echo "3. Open your browser and navigate to:"
echo "   ${GREEN}http://localhost:8000${NC}"
echo ""
echo "4. Register a new user at:"
echo "   ${GREEN}http://localhost:8000/register${NC}"
echo ""
echo "5. To make a user an admin, run:"
echo "   ${GREEN}sqlite3 filemanager.db${NC}"
echo "   ${GREEN}UPDATE users SET role = 'ADMIN' WHERE username = 'your-username';${NC}"
echo ""
echo "================================================"
echo "   API Documentation will be available at:"
echo "   ${GREEN}http://localhost:8000/docs${NC}"
echo "================================================"
echo ""
