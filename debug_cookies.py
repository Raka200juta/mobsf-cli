#!/usr/bin/env python3
import requests
import re

def find_api_key():
    print("🔍 Finding API key after login...")
    
    session = requests.Session()
    
    # Step 1: Login
    print("\n1. Logging in...")
    login_page = session.get("http://127.0.0.1:8000/login/")
    csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
    
    if csrf_match:
        login_data = {
            'username': 'mobsf',
            'password': 'mobsf',
            'csrfmiddlewaretoken': csrf_match.group(1)
        }
        
        headers = {
            'Referer': 'http://127.0.0.1:8000/login/',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        session.post("http://127.0.0.1:8000/login/", data=login_data, headers=headers)
        print("   ✅ Logged in")
    
    # Step 2: Access settings page to find API key
    print("\n2. Checking settings page...")
    settings_page = session.get("http://127.0.0.1:8000/settings/")
    
    # Look for API key in settings
    api_key_patterns = [
        r'API[_\s-]*Key[^>]*>([^<]+)<',
        r'api[_\s-]*key[^>]*>([^<]+)<',
        r'"api_key"[^>]*>([^<]+)<',
        r'value=["\']([a-f0-9]{64})["\']',
    ]
    
    for pattern in api_key_patterns:
        matches = re.findall(pattern, settings_page.text, re.IGNORECASE)
        if matches:
            print(f"   ✅ API key found: {matches[0]}")
            return matches[0]
    
    # Step 3: Check profile or account page
    print("\n3. Checking profile page...")
    profile_page = session.get("http://127.0.0.1:8000/profile/")
    for pattern in api_key_patterns:
        matches = re.findall(pattern, profile_page.text, re.IGNORECASE)
        if matches:
            print(f"   ✅ API key found in profile: {matches[0]}")
            return matches[0]
    
    # Step 4: Check page source for any API key
    print("\n4. Scanning page source for API key...")
    all_text = settings_page.text + profile_page.text
    hex_pattern = r'[a-f0-9]{64}'
    hex_matches = re.findall(hex_pattern, all_text)
    if hex_matches:
        print(f"   Found hex strings: {hex_matches[:3]}")
    
    print("   ❌ API key not found in web pages")
    return None

def test_api_with_key_and_session():
    print("\n5. Testing API with session + potential keys...")
    
    session = requests.Session()
    
    # Login first
    login_page = session.get("http://127.0.0.1:8000/login/")
    csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
    
    if csrf_match:
        login_data = {
            'username': 'mobsf',
            'password': 'mobsf', 
            'csrfmiddlewaretoken': csrf_match.group(1)
        }
        headers = {
            'Referer': 'http://127.0.0.1:8000/login/',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        session.post("http://127.0.0.1:8000/login/", data=login_data, headers=headers)
    
    # Test with session only
    print("   Testing with session only...")
    test_response = session.get("http://127.0.0.1:8000/api/v1/upload")
    print(f"   Session only: Status {test_response.status_code}")
    
    # Test with Authorization header
    print("   Testing with Authorization header...")
    test_files = {'file': ('test.txt', b'test content')}
    test_response = session.post("http://127.0.0.1:8000/api/v1/upload", files=test_files)
    print(f"   With file upload: Status {test_response.status_code}")
    
    if test_response.status_code == 200:
        print(f"   ✅ SUCCESS! Response: {test_response.json()}")

if __name__ == "__main__":
    api_key = find_api_key()
    test_api_with_key_and_session()