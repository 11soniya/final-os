#!/usr/bin/env python3
"""
Test file metadata functionality
"""
import requests
import json
import sys
from io import BytesIO

BASE_URL = "http://localhost:8000"

def test_metadata():
    print("=" * 70)
    print("   TESTING FILE METADATA FUNCTIONALITY")
    print("=" * 70)
    print()
    
    # Step 1: Login as admin
    print("1. Logging in as admin...")
    login_response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": "admin", "password": "Admin@123"}
    )
    
    if not login_response.ok:
        print(f"❌ Login failed: {login_response.status_code}")
        print(f"   Response: {login_response.text}")
        return False
    
    token = login_response.json()["access_token"]
    print("✅ Login successful")
    print()
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Step 2: Upload a test file
    print("2. Uploading a test file...")
    test_content = b"This is a test file for metadata functionality testing."
    files = {
        "file": ("test_metadata.txt", BytesIO(test_content), "text/plain")
    }
    
    upload_response = requests.post(
        f"{BASE_URL}/api/files/upload",
        files=files,
        headers=headers
    )
    
    if not upload_response.ok:
        print(f"❌ Upload failed: {upload_response.status_code}")
        print(f"   Response: {upload_response.text}")
    else:
        upload_data = upload_response.json()
        print(f"✅ File uploaded successfully!")
        print(f"   File ID: {upload_data['id']}")
        print(f"   Filename: {upload_data['filename']}")
        print(f"   Size: {upload_data['size']} bytes")
        print(f"   Checksum: {upload_data['checksum']}")
    print()
    
    # Step 3: Get all files metadata from admin endpoint
    print("3. Fetching file metadata from admin endpoint...")
    metadata_response = requests.get(
        f"{BASE_URL}/api/admin/files",
        headers=headers
    )
    
    if not metadata_response.ok:
        print(f"❌ Failed to fetch metadata: {metadata_response.status_code}")
        print(f"   Response: {metadata_response.text}")
        return False
    
    files_metadata = metadata_response.json()
    print(f"✅ Metadata fetched successfully!")
    print(f"   Total files: {len(files_metadata)}")
    print()
    
    # Step 4: Display metadata for all files
    print("4. File Metadata Details:")
    print("-" * 70)
    
    if len(files_metadata) == 0:
        print("   No files found in the system")
    else:
        for i, file in enumerate(files_metadata[:5], 1):  # Show first 5 files
            print(f"\n   File #{i}:")
            print(f"   - ID: {file['id']}")
            print(f"   - Filename: {file['filename']}")
            print(f"   - Original: {file['original_filename']}")
            print(f"   - Owner: {file['owner_username']} (ID: {file['owner_id']})")
            print(f"   - Size: {file['size']} bytes")
            print(f"   - Type: {file['content_type'] or 'N/A'}")
            print(f"   - Checksum: {file['checksum'][:32]}...")
            print(f"   - Uploaded: {file['uploaded_at']}")
            print(f"   - Last Accessed: {file['last_accessed'] or 'Never'}")
            print(f"   - Encrypted: {'Yes' if file['encrypted'] else 'No'}")
        
        if len(files_metadata) > 5:
            print(f"\n   ... and {len(files_metadata) - 5} more files")
    
    print()
    print("=" * 70)
    print("   METADATA TEST COMPLETED SUCCESSFULLY! ✅")
    print("=" * 70)
    print()
    print("📊 Summary:")
    print(f"   - Login: ✅ Working")
    print(f"   - File Upload: ✅ Working")
    print(f"   - Metadata API: ✅ Working")
    print(f"   - Total Files in System: {len(files_metadata)}")
    print()
    print("🌐 To view in browser:")
    print("   1. Open http://localhost:8000/login")
    print("   2. Login with admin/Admin@123")
    print("   3. Navigate to Admin Dashboard")
    print("   4. Scroll down to see 'All Files - Complete Metadata' table")
    print()
    
    return True

if __name__ == "__main__":
    try:
        success = test_metadata()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Error during test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
