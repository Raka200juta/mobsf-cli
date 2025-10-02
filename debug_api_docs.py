#!/usr/bin/env python3
import requests
import re

def login_and_get_api_docs():
    print("🔐 Logging in and accessing API docs...")
    
    session = requests.Session()
    
    # Step 1: Get login page
    print("\n1. Getting login page...")
    login_page = session.get("http://localhost:8000/login/")
    print(f"   Status: {login_page.status_code}")
    
    # Step 2: Extract CSRF token
    csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
    if not csrf_match:
        print("   ❌ CSRF token not found!")
        return None
    
    csrf_token = csrf_match.group(1)
    print(f"   ✅ CSRF token: {csrf_token[:30]}...")
    
    # Step 3: Login with redirect to /api_docs
    print("\n2. Logging in with redirect to /api_docs...")
    login_data = {
        'username': 'mobsf',
        'password': 'mobsf',
        'csrfmiddlewaretoken': csrf_token
    }
    
    headers = {
        'Referer': 'http://localhost:8000/login/',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    # Login with redirect to /api_docs
    login_response = session.post(
        "http://localhost:8000/login/?next=/api_docs",
        data=login_data,
        headers=headers,
        allow_redirects=True
    )
    
    print(f"   Login status: {login_response.status_code}")
    print(f"   Final URL: {login_response.url}")
    print(f"   Session cookies: {dict(session.cookies)}")
    
    # Step 4: Access API docs with session
    print("\n3. Accessing API docs with session...")
    api_docs_response = session.get("http://localhost:8000/api_docs")
    print(f"   API docs status: {api_docs_response.status_code}")
    
    # Step 5: Save and analyze API docs content
    print("\n4. Analyzing API docs content...")
    with open("api_docs_after_login.html", "w", encoding='utf-8') as f:
        f.write(api_docs_response.text)
    print("   ✅ API docs saved to api_docs_after_login.html")
    
    # Step 6: Search for API key
    print("\n5. Searching for API key...")
    
    # Look for any api_key mentions
    api_key_contexts = re.findall(r'.{0,200}api[\s_-]*key.{0,200}', api_docs_response.text, re.IGNORECASE)
    for i, context in enumerate(api_key_contexts[:10]):
        print(f"   Context {i+1}: {context}")
    
    # Look for 64-character strings
    hex_strings = re.findall(r'[a-fA-F0-9]{64}', api_docs_response.text)
    print(f"   Found {len(hex_strings)} hex strings:")
    for hex_str in hex_strings[:10]:
        print(f"     → {hex_str}")
    
    # Look for JSON structures
    json_structures = re.findall(r'\{[^}]{0,500}api[\s_-]*key[^}]{0,500}\}', api_docs_response.text, re.IGNORECASE)
    for i, json_str in enumerate(json_structures[:5]):
        print(f"   JSON structure {i+1}: {json_str}")
    
    return session, api_docs_response.text

if __name__ == "__main__":
    session, api_docs_content = login_and_get_api_docs()
    
    if session and api_docs_content:
        print("\n🎉 Successfully accessed authenticated API docs!")
        print("🔍 Check api_docs_after_login.html for the full content")
    else:
        print("\n❌ Failed to access API docs")