#!/usr/bin/env python3
import requests
import re

def debug_api_docs():
    mobsf_url = "http://localhost:8000"
    
    try:
        response = requests.get(f"{mobsf_url}/api_docs", timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Content Type: {response.headers.get('content-type')}")
        print("\n=== First 1000 characters of response ===")
        print(response.text[:1000])
        print("\n=== Searching for API key patterns ===")
        
        # Coba berbagai pola
        patterns = [
            r'\b([a-f0-9]{64})\b',  # Pattern original
            r'[A-Fa-f0-9]{64}',     # Pattern alternatif
            r'api_key["\']?\s*:\s*["\']([^"\']+)["\']',  # JSON pattern
            r'Authorization["\']?\s*:\s*["\']([^"\']+)["\']',  # Header pattern
        ]
        
        for i, pattern in enumerate(patterns):
            matches = re.findall(pattern, response.text)
            print(f"Pattern {i+1}: {pattern}")
            print(f"Matches found: {len(matches)}")
            for match in matches[:3]:  # Tampilkan 3 hasil pertama
                print(f"  - {match}")
            print()
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    debug_api_docs()