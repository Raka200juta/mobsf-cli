#!/usr/bin/env python3

import requests
import json
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent / 'config.json'

def load_config():
    """Load configuration from config.json"""
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning("config.json not found, using defaults")
        return {
            "mobsf_url": "http://127.0.0.1:8000", 
            "username": "mobsf", 
            "password": "mobsf",
            "session_cookie": ""
        }
    except json.JSONDecodeError as e:
        logger.error(f"Invalid config.json: {e}")
        return {
            "mobsf_url": "http://127.0.0.1:8000", 
            "username": "mobsf", 
            "password": "mobsf",
            "session_cookie": ""
        }

def save_config(config):
    """Save configuration to config.json"""
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        logger.info("Config saved successfully")
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
            response = requests.get("http://127.0.0.1:8000/api_docs", timeout=10)
            if response.status_code == 200:
                logger.info("✅ MobSF API docs are accessible")
                return True
        except Exception as e:
            logger.debug(f"⏳ Still waiting... {e}")
        
        time.sleep(5)
    
    logger.error("❌ MobSF not ready within timeout")
    return False

def login_to_mobsf(username, password):
    """Login to MobSF and get session cookie"""
    try:
        logger.info(f"🔐 Logging in as {username}...")
        
        # Create session to maintain cookies
        session = requests.Session()
        
        # First, get the login page to obtain CSRF token
        logger.info("📋 Getting login page...")
        login_page = session.get("http://127.0.0.1:8000/login/", timeout=10)
        
        # Debug: print available cookies
        logger.debug(f"Initial cookies: {dict(session.cookies)}")
        
        # Extract CSRF token from the form
        import re
        csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
        
        if not csrf_match:
            # Try alternative pattern
            csrf_match = re.search(r'csrfmiddlewaretoken["\']?\\s*[:=]\\s*["\']([^"\']+)["\']', login_page.text)
            if not csrf_match:
                logger.error("❌ CSRF token not found in login page")
                logger.debug(f"Login page snippet: {login_page.text[:500]}")
                return None
        
        csrf_token = csrf_match.group(1)
        logger.info(f"✅ CSRF token found: {csrf_token[:20]}...")
        
        # Prepare login data
        login_data = {
            'username': username,
            'password': password,
            'csrfmiddlewaretoken': csrf_token
        }
        
        # Set required headers
        headers = {
            'Referer': 'http://127.0.0.1:8000/login/',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        # Perform login
        logger.info("📤 Sending login request...")
        login_response = session.post(
            "http://127.0.0.1:8000/login/",
            data=login_data,
            headers=headers,
            timeout=10,
            allow_redirects=True  # Follow redirects to see final response
        )
        
        # Debug: print all cookies after login
        logger.debug(f"Cookies after login: {dict(session.cookies)}")
        
        # Check if login was successful by looking for session cookie
        session_cookie = None
        
        # Try multiple possible cookie names
        possible_cookie_names = ['sessionid', 'session', 'session_id', 'mobsf_session']
        for cookie_name in possible_cookie_names:
            if cookie_name in session.cookies:
                session_cookie = session.cookies.get(cookie_name)
                logger.info(f"✅ Found session cookie '{cookie_name}': {session_cookie[:20]}...")
                break
        
        if not session_cookie:
            # If no named cookie found, try to get the first cookie
            cookies_dict = dict(session.cookies)
            if cookies_dict:
                first_cookie_name = list(cookies_dict.keys())[0]
                session_cookie = cookies_dict[first_cookie_name]
                logger.info(f"✅ Using first available cookie '{first_cookie_name}': {session_cookie[:20]}...")
            else:
                logger.error("❌ No cookies found after login")
                logger.debug(f"Login response status: {login_response.status_code}")
                logger.debug(f"Login response headers: {dict(login_response.headers)}")
                return None
        
        # Verify login by accessing a protected page
        logger.info("🔍 Verifying login...")
        test_response = session.get("http://127.0.0.1:8000/", timeout=10)
        
        if test_response.status_code == 200 and "MobSF" in test_response.text:
            logger.info("✅ Login verification successful!")
            return session_cookie
        else:
            logger.error("❌ Login verification failed")
            return None
            
    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        return None

def test_api_with_session(session_cookie):
    """Test if we can access API with session cookie"""
    try:
        headers = {
            'Cookie': f'sessionid={session_cookie}',
        }
        
        response = requests.get(
            "http://127.0.0.1:8000/api/v1/upload", 
            headers=headers, 
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info("✅ API access successful with session")
            return True
        else:
            # Try alternative cookie name
            headers = {
                'Cookie': f'{session_cookie}',
            }
            response = requests.get(
                "http://127.0.0.1:8000/api/v1/upload", 
                headers=headers, 
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("✅ API access successful with raw cookie")
                return True
            else:
                logger.error(f"❌ API test failed: {response.status_code}")
                return False
            
    except Exception as e:
        logger.error(f"❌ API test error: {e}")
        return False

def grab_api_key():
    """Main function - now handles login instead of API key"""
    # Wait for MobSF to be ready
    if not wait_for_mobsf_ready():
        return None
    
    config = load_config()
    username = config.get('username', 'mobsf')
    password = config.get('password', 'mobsf')
    
    # Try to login
    session_cookie = login_to_mobsf(username, password)
    
    if session_cookie:
        # Test the session
        if test_api_with_session(session_cookie):
            # Save session to config
            config['session_cookie'] = session_cookie
            if save_config(config):
                logger.info("✅ Session saved to config")
            return session_cookie
        else:
            logger.error("❌ Session test failed")
            return None
    else:
        logger.error("❌ Failed to authenticate with MobSF")
        return None