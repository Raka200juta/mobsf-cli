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
    """Load configuration from config.json and return the entire config dictionary."""
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
            logger.info(f"Loaded existing {CONFIG_PATH.name}")
            return config
    except FileNotFoundError:
        logger.warning(f"{CONFIG_PATH.name} not found, using defaults.")
        # Return default config structure
        default_config = {
            "mobsf_url": "http://localhost:8000",
            "username": "mobsf", # <-- Tambahkan default username
            "password": "mobsf", # <-- Tambahkan default password
            "session_cookie": "",
            "api_key": ""
        }
        # Simpan default config ke file jika belum ada
        save_config(default_config)
        return default_config
    except json.JSONDecodeError as e:
        logger.error(f"Invalid {CONFIG_PATH.name}: {e}")
        # Return default config on error as fallback
        return {
            "mobsf_url": "http://localhost:8000",
            "username": "mobsf", # <-- Default username
            "password": "mobsf", # <-- Default password
            "session_cookie": "",
            "api_key": ""
        }

def save_config(config):
    """Save configuration dictionary to config.json"""
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        logger.info(f"✅ {CONFIG_PATH.name} saved successfully.")
        return True
    except Exception as e:
        logger.error(f"Failed to save {CONFIG_PATH.name}: {e}")
        return False

def wait_for_mobsf_ready(timeout=120):
    """Wait for MobSF to be accessible"""
    logger.info("⏳ Waiting for MobSF to be ready...")
    # Gunakan URL dari config, default ke localhost jika tidak ada
    config = load_config() # Ambil config terbaru
    mobsf_url = config.get("mobsf_url", "http://localhost:8000").rstrip('/')

    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # Gunakan URL dari config
            response = requests.get(f"{mobsf_url}/login/", timeout=10)
            if response.status_code == 200:
                logger.info("✅ MobSF login page is accessible")
                return True
        except Exception as e:
            logger.debug(f"⏳ Still waiting... {e}")

        time.sleep(5)

    logger.error("❌ MobSF not ready within timeout")
    return False

def login_to_mobsf(username, password):
    """Login to MobSF and return session object and session cookie."""
    # Gunakan URL dari config
    config = load_config() # Ambil config terbaru
    mobsf_url = config.get("mobsf_url", "http://localhost:8000").rstrip('/')
    try:
        logger.info(f"🔐 Logging in as {username}...")

        session = requests.Session()

        # Get login page for CSRF token
        login_page_url = f"{mobsf_url}/login/"
        login_page = session.get(login_page_url, timeout=10)

        # Extract CSRF token
        csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
        if not csrf_match:
            logger.error("❌ CSRF token not found on login page.")
            logger.debug("Login page content snippet (first 1000 chars):")
            logger.debug(login_page.text[:1000])
            return None, None

        csrf_token = csrf_match.group(1)
        logger.info(f"✅ CSRF token: {csrf_token[:20]}...")

        # Prepare login data - sesuaikan nama field jika perlu
        login_data = {
            'username': username,
            'password': password,
            'csrfmiddlewaretoken': csrf_token
        }

        headers = {
            'Referer': login_page_url,
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        # Perform login (follow redirects)
        login_response = session.post(
            login_page_url, # Kirim ke URL login utama
            data=login_data,
            headers=headers,
            timeout=10,
            allow_redirects=True  # Follow redirects
        )

        # Debug: Simpan respons login jika gagal
        if login_response.status_code != 200 or '/login/' in login_response.url:
            logger.error(f"❌ Login failed with status {login_response.status_code} or still on login page.")
            logger.debug(f"Final login URL: {login_response.url}")
            # Cek apakah ada pesan error di halaman
            error_match = re.search(r'<div class="alert alert-danger[^>]*>(.*?)</div>', login_response.text, re.DOTALL | re.IGNORECASE)
            if error_match:
                error_text = error_match.group(1).strip()
                logger.error(f"Login page error message: {error_text}")
            else:
                 logger.debug("No obvious error message found in response.")
            logger.debug(f"Response text (first 1000 chars): {login_response.text[:1000]}")
            return None, None
        elif login_response.status_code == 200 and '/login/' not in login_response.url:
            logger.info(f"✅ Login successful! Redirected to: {login_response.url}")

            # Get session cookie - name might vary, common ones are sessionid, session
            session_cookie_names = ['sessionid', 'session', 'csrftoken']
            session_cookie = None
            for name in session_cookie_names:
                 session_cookie = session.cookies.get(name)
                 if session_cookie:
                     logger.info(f"✅ Found session cookie ({name}): {session_cookie[:20]}...")
                     break

            if not session_cookie:
                 logger.warning("⚠ No standard session cookie found, but login might still be valid for API key extraction.")
                 # We might still be able to extract the API key from the response URL or content if logged in
                 # For now, we'll continue without the cookie, relying on the session object's cookies being used in the next request

            return session, session_cookie
        else:
            logger.error(f"❌ Login failed with unexpected status or redirect pattern: {login_response.status_code}, URL: {login_response.url}")
            logger.debug(f"Response text (first 1000 chars): {login_response.text[:1000]}")
            return None, None

    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        return None, None

def extract_api_key_from_docs(session):
    """Extract API key from /api_docs or /dashboard page after login."""
    # Gunakan URL dari config
    config = load_config() # Ambil config terbaru
    mobsf_url = config.get("mobsf_url", "http://localhost:8000").rstrip('/')

    try:
        logger.info("📖 Accessing API documentation/dashboard after login...")

        # Access API docs with the authenticated session
        # Try both common endpoints where API key might be displayed
        api_docs_urls = [f"{mobsf_url}/api_docs", f"{mobsf_url}/api/", f"{mobsf_url}/dashboard/"]
        api_key = None
        content_source = "unknown"

        for docs_url in api_docs_urls:
            try:
                logger.debug(f"Trying to access {docs_url}")
                response = session.get(docs_url, timeout=10)

                if response.status_code == 200:
                    logger.info(f"✅ Successfully accessed {docs_url}")
                    content_source = docs_url

                    # Save the page content for manual inspection if needed
                    filename = f"api_docs_content_{docs_url.split('/')[-1]}.html"
                    with open(filename, "w", encoding='utf-8') as f:
                        f.write(response.text)
                    logger.info(f"📋 Saved content to {filename}")

                    # --- Improved API Key Extraction ---
                    text = response.text

                    # Pattern 1: Look for 'Authorization' or 'API Key' followed by the key
                    # This is common in API documentation pages
                    auth_patterns = [
                        r'Authorization[\'"]?\s*[:=]\s*[\'"]?([a-f0-9]{64})[\'"]?', # Authorization: <key> or Authorization=<key>
                        r'API[\'"]?\s*Key[\'"]?\s*[:=]\s*[\'"]?([a-f0-9]{64})[\'"]?', # API Key: <key>
                        r'"api_key"\s*:\s*"([a-f0-9]{64})"', # JSON-like "api_key": "..."
                        r"'api_key'\s*:\s*'([a-f0-9]{64})'", # JSON-like 'api_key': '...'
                    ]

                    for pattern in auth_patterns:
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match:
                            api_key = match.group(1)
                            logger.info(f"✅ Found API key using pattern '{pattern}': {api_key[:16]}...")
                            break # Stop if found with this pattern
                    if api_key:
                        break # Stop if found on this page

                    # Pattern 2: Look for any 64-character hex string that *might* be the API key
                    # This is a fallback, less reliable
                    hex_pattern = r'\b([a-f0-9]{64})\b'
                    hex_matches = re.findall(hex_pattern, text, re.IGNORECASE)
                    if hex_matches:
                        # Filter potential matches (e.g., remove known non-API-key hashes)
                        # For now, just take the first one that isn't obviously a hash (like CSRF)
                        for potential_key in hex_matches:
                            # Simple filter: if it's not the CSRF token we just grabbed, it might be the API key
                            # This is imperfect, but often the API key is unique.
                            # A better filter would require knowing more about the page structure.
                            if len(potential_key) == 64 and not potential_key.startswith('csrf'): # Basic check
                                 api_key = potential_key
                                 logger.info(f"🔍 Found potential 64-char hex string (fallback): {api_key[:16]}...")
                                 # Note: This might be a false positive. The first successful auth pattern is preferred.
                                 break
                        if api_key:
                             break # Stop if found with fallback on this page

            except requests.exceptions.RequestException as e:
                 logger.warning(f"⚠ Could not access {docs_url}: {e}")
                 continue # Try the next URL

        if api_key:
            logger.info(f"✅ Extracted API key from {content_source}: {api_key[:16]}...")
            return api_key
        else:
            logger.error("❌ Could not find API key in any of the accessed pages.")
            logger.info("🔍 Check the saved HTML files for manual inspection.")
            return None

    except Exception as e:
        logger.error(f"❌ Error accessing API docs: {e}")
        return None


def test_api_key(api_key):
    """Test if the API key works by making an authenticated request."""
    # Gunakan URL dari config
    config = load_config() # Ambil config terbaru
    mobsf_url = config.get("mobsf_url", "http://localhost:8000").rstrip('/')

    try:
        logger.info("🧪 Testing API key...")
        headers = {'Authorization': api_key}

        # Test with a simple GET request to the scans endpoint
        response = requests.get(
            f"{mobsf_url}/api/v1/scans",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            logger.info("✅ API key test successful!")
            return True
        elif response.status_code == 401:
            logger.error("❌ API key test failed: Unauthorized (401). Key might be invalid.")
        elif response.status_code == 403:
            logger.error("❌ API key test failed: Forbidden (403). Key might lack permissions.")
        else:
            logger.error(f"❌ API key test failed: Status {response.status_code}. Response: {response.text[:200]}...")

    except requests.exceptions.RequestException as e:
        logger.error(f"❌ API test request error: {e}")
    except Exception as e:
        logger.error(f"❌ API test error: {e}")

    return False


def grab_api_key():
    """
    Main function: login to MobSF, extract API key, save config, return key.
    Returns the API key if successful, None otherwise.
    """
    if not wait_for_mobsf_ready():
        return None

    config = load_config() # Ambil config terbaru
    username = config.get('username', 'mobsf') # Ambil dari config
    password = config.get('password', 'mobsf') # Ambil dari config

    # 1. Login
    session, session_cookie = login_to_mobsf(username, password)
    if not session:
        logger.error("❌ Login process failed.")
        return None

    # 2. Extract API Key
    api_key = extract_api_key_from_docs(session)
    if not api_key:
        logger.error("❌ Failed to extract API key from documentation.")
        return None

    # 3. Test API Key
    if test_api_key(api_key):
        logger.info("✅ API key validated successfully!")

        # 4. Update and Save Config
        config['session_cookie'] = session_cookie or "" # Ensure it's a string
        config['api_key'] = api_key
        if save_config(config):
            logger.info("✅ Updated config.json with new API key.")
        else:
            logger.error("❌ Failed to save config.json with new API key.")

        return api_key  # Return the key for mobsf_cli.py
    else:
        logger.error("❌ Extracted API key failed the test.")
        return None


if __name__ == "__main__":
    # If run directly, attempt to grab the API key
    api_key = grab_api_key()
    if api_key:
        print(f"✅ API key obtained and config saved: {api_key[:16]}...")
    else:
        print("❌ Failed to get or validate API key.")
        print("   Check the logs and the saved HTML files for debugging clues.")
        print("   Ensure the username/password in config.json are correct.")
        print("   Ensure MobSF is running and accessible at the configured URL.")