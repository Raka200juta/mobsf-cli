#!/usr/bin/env python3

import requests
import json
import time
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent / 'config.json'

def load_config():
    """Load configuration from config.json"""
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "mobsf_url": "http://localhost:8000", 
            "username": "mobsf", 
            "password": "mobsf",
            "session_cookie": "",
            "api_key": ""
        }
    except json.JSONDecodeError as e:
        logger.error(f"Invalid config.json: {e}")
        return {
            "mobsf_url": "http://localhost:8000", 
            "username": "mobsf", 
            "password": "mobsf",
            "session_cookie": "",
            "api_key": ""
        }

def save_config(config):
    """Save configuration to config.json"""
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        return False

def wait_for_mobsf_ready(timeout=120):
    """Wait for MobSF to be accessible"""
    logger.info("⏳ Waiting for MobSF to be ready...")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get("http://localhost:8000/login/", timeout=10)
            if response.status_code == 200:
                logger.info("✅ MobSF login page is accessible")
                return True
        except Exception as e:
            logger.debug(f"⏳ Still waiting... {e}")
        
        time.sleep(5)
    
    logger.error("❌ MobSF not ready within timeout")
    return False

def login_to_mobsf(username, password):
    """Login to MobSF and return session"""
    try:
        logger.info(f"🔐 Logging in as {username}...")
        
        session = requests.Session()
        
        # Get login page for CSRF token
        login_page = session.get("http://localhost:8000/login/", timeout=10)
        
        # Extract CSRF token
        csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
        if not csrf_match:
            logger.error("❌ CSRF token not found")
            return None, None
        
        csrf_token = csrf_match.group(1)
        logger.info(f"✅ CSRF token: {csrf_token[:20]}...")
        
        # Prepare login data
        login_data = {
            'username': username,
            'password': password,
            'csrfmiddlewaretoken': csrf_token
        }
        
        headers = {
            'Referer': 'http://localhost:8000/login/',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        # Perform login (follow redirects to /api_docs)
        login_response = session.post(
            "http://localhost:8000/login/?next=/api_docs",
            data=login_data,
            headers=headers,
            timeout=10,
            allow_redirects=True  # Follow redirect to /api_docs
        )
        
        # Check if login was successful
        if login_response.status_code == 200 and 'api_docs' in login_response.url:
            logger.info("✅ Login successful! Redirected to API docs")
            
            # Get session cookie
            session_cookie = session.cookies.get('sessionid')
            if session_cookie:
                logger.info(f"✅ Session cookie: {session_cookie[:20]}...")
                return session, session_cookie
            else:
                logger.error("❌ No session cookie found")
                return None, None
        else:
            logger.error(f"❌ Login failed or not redirected to API docs. Status: {login_response.status_code}")
            logger.debug(f"Final URL: {login_response.url}")
            return None, None
            
    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        return None, None

def extract_api_key_from_docs(session):
    """Extract API key from /api_docs page after login"""
    try:
        logger.info("📖 Accessing API docs after login...")
        
        # Access API docs with authenticated session
        api_docs_response = session.get("http://localhost:8000/api_docs", timeout=10)
        
        if api_docs_response.status_code == 200:
            logger.info("✅ Successfully accessed API docs")
            
            # Save API docs content for debugging
            with open("api_docs_authenticated.html", "w", encoding='utf-8') as f:
                f.write(api_docs_response.text)
            logger.info("✅ Authenticated API docs saved to api_docs_authenticated.html")
            
            # Look for API key in various formats
            patterns = [
                r'"api_key"\s*:\s*"([a-f0-9]{64})"',
                r"'api_key'\s*:\s*'([a-f0-9]{64})'",
                r"API_KEY\s*[=:]\s*'([a-f0-9]{64})",
                r'API_KEY\s*[=:]\s*"([a-f0-9]{64})',
                r"api_key\s*[=:]\s*['\"]([a-f0-9]{64})['\"]",
                r"default.*['\"]([a-f0-9]{64})['\"]",
                r"value.*['\"]([a-f0-9]{64})['\"]",
                r"example.*['\"]([a-f0-9]{64})['\"]",
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, api_docs_response.text, re.IGNORECASE)
                if matches:
                    api_key = matches[0]
                    logger.info(f"✅ API key found: {api_key[:16]}...")
                    return api_key
            
            # Look for any 64-character hex string
            hex_pattern = r'\b[a-f0-9]{64}\b'
            hex_matches = re.findall(hex_pattern, api_docs_response.text, re.IGNORECASE)
            if hex_matches:
                logger.info(f"✅ Found hex strings: {hex_matches[:3]}")
                # Use the first one as potential API key
                potential_key = hex_matches[0]
                logger.info(f"✅ Using as API key: {potential_key[:16]}...")
                return potential_key
            
            # If no API key found, check the content
            logger.error("❌ API key not found in authenticated API docs")
            logger.info("📋 Checking API docs content structure...")
            
            # Look for any mention of api_key
            api_key_mentions = re.findall(r'api[\s_-]*key[^"]*"?[^"]*"?', api_docs_response.text, re.IGNORECASE)
            for mention in api_key_mentions[:5]:
                logger.info(f"   API key mention: {mention[:100]}...")
            
            return None
        else:
            logger.error(f"❌ Failed to access API docs: {api_docs_response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"❌ Error accessing API docs: {e}")
        return None

def test_api_key(api_key, session_cookie=None):
    """Test if the API key works"""
    try:
        logger.info("🧪 Testing API key...")
        
        headers = {'Authorization': api_key}
        if session_cookie:
            headers['Cookie'] = f'sessionid={session_cookie}'
        
        # Test with scans endpoint (read-only GET request)
        response = requests.get(
            "http://localhost:8000/api/v1/scans", 
            headers=headers, 
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info("✅ API key works!")
            return True
        else:
            logger.error(f"❌ API key test failed: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ API test error: {e}")
        return False

def grab_api_key():
    """Main function - login and extract API key from docs"""
    if not wait_for_mobsf_ready():
        return None
    
    config = load_config()
    username = config.get('username', 'mobsf')
    password = config.get('password', 'mobsf')
    
    # Login to MobSF
    session, session_cookie = login_to_mobsf(username, password)
    if not session or not session_cookie:
        return None
    
    # Extract API key from authenticated API docs
    api_key = extract_api_key_from_docs(session)
    if not api_key:
        return None
    
    # Test the API key
    if test_api_key(api_key, session_cookie):
        logger.info("✅ API authentication successful!")
        
        # Save to config
        config['session_cookie'] = session_cookie
        config['api_key'] = api_key
        
        if save_config(config):
            logger.info("✅ Credentials saved to config")
        
        return api_key
    else:
        logger.error("❌ API key test failed")
        return None