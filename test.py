#!/usr/bin/env python3
import os
import sys
import json
import time
import logging
import sqlite3
import tempfile
import subprocess
from pathlib import Path
import requests
from requests.exceptions import RequestException
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
console = Console()

# Import analysis modules
try:
    from permission_behavior_android import analyze_permissions_enhanced as analyze_android_perms
    print("✅ Android analysis modules imported successfully")
except ImportError as e:
    print(f"❌ Failed to import Android analysis: {e}")

try:
    from permission_behavior_ios import analyze_ios_permissions_enhanced as analyze_ios_perms
    print("✅ iOS analysis modules imported successfully")
except ImportError as e:
    print(f"❌ Failed to import iOS analysis: {e}")

def get_container_db():
    """Extract database from Docker container and get API key"""
    console.print("[yellow]🔍 Extracting API key from MobSF container...[/yellow]")
    
    try:
        # Get container ID
        result = subprocess.run(
            ["docker", "ps", "--filter", "ancestor=opensecurity/mobile-security-framework-mobsf:latest", "--format", "{{.ID}}"],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode != 0 or not result.stdout.strip():
            console.print("[red]❌ MobSF container not found[/red]")
            return None
        
        container_id = result.stdout.strip()
        console.print(f"[dim]Found container: {container_id}[/dim]")
        
        # Create temporary file for database
        with tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False) as temp_db:
            temp_db_path = temp_db.name
        
        # Copy database from container
        copy_result = subprocess.run(
            ["docker", "cp", f"{container_id}:/home/mobsf/.MobSF/db.sqlite3", temp_db_path],
            capture_output=True, text=True, timeout=30
        )
        
        if copy_result.returncode != 0:
            console.print(f"[red]❌ Failed to copy database: {copy_result.stderr}[/red]")
            os.unlink(temp_db_path)
            return None
        
        console.print("[green]✅ Database copied from container[/green]")
        
        # Query API key from database
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        
        # Try to find API key in various tables
        queries = [
            "SELECT name, value FROM django_q_ormq WHERE name LIKE '%api%' OR name LIKE '%key%'",
            "SELECT key, value FROM django_session WHERE key LIKE '%api%'",
            "SELECT * FROM auth_user WHERE username = 'mobsf'",
        ]
        
        api_key = None
        
        for query in queries:
            try:
                cursor.execute(query)
                rows = cursor.fetchall()
                for row in rows:
                    # Look for 64-character hex strings in any field
                    for field in row:
                        if field and isinstance(field, str):
                            import re
                            hex_matches = re.findall(r'\b[a-fA-F0-9]{64}\b', str(field))
                            if hex_matches:
                                api_key = hex_matches[0]
                                console.print(f"[green]✅ Found API key in database![/green]")
                                break
                    if api_key:
                        break
            except sqlite3.Error as e:
                continue
        
        conn.close()
        os.unlink(temp_db_path)
        
        return api_key
        
    except Exception as e:
        console.print(f"[red]❌ Error extracting API key: {e}[/red]")
        return None

def get_api_key_direct():
    """Get API key directly from running MobSF instance"""
    mobsf_url = "http://localhost:8000"
    
    # Method 1: Try to get from database first (most reliable)
    api_key = get_container_db()
    if api_key:
        return api_key, mobsf_url
    
    # Method 2: Fallback to login approach
    console.print("[yellow]🔄 Falling back to login method...[/yellow]")
    
    try:
        import re
        session = requests.Session()
        
        # Get login page
        login_page = session.get(f"{mobsf_url}/login/", timeout=10)
        csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
        
        if not csrf_match:
            return None, mobsf_url
        
        # Login
        login_data = {
            'csrfmiddlewaretoken': csrf_match.group(1),
            'username': 'mobsf',
            'password': 'mobsf',
        }
        
        login_response = session.post(
            f"{mobsf_url}/login/",
            data=login_data,
            headers={'Referer': f"{mobsf_url}/login/"},
            timeout=10,
            allow_redirects=False
        )
        
        if login_response.status_code == 302:
            # Get API docs
            docs_response = session.get(f"{mobsf_url}/api_docs", timeout=10)
            hex_matches = re.findall(r'\b[a-fA-F0-9]{64}\b', docs_response.text)
            if hex_matches:
                return hex_matches[0], mobsf_url
                
    except Exception as e:
        console.print(f"[red]❌ Login method failed: {e}[/red]")
    
    return None, mobsf_url

def ensure_mobsf_connection():
    """Ensure we can connect to MobSF"""
    mobsf_url = "http://localhost:8000"
    
    console.print("[yellow]🔗 Connecting to MobSF...[/yellow]")
    
    # Get API key
    api_key, mobsf_url = get_api_key_direct()
    
    if not api_key:
        console.print("[red]❌ Could not obtain API key[/red]")
        console.print("[yellow]Please ensure MobSF container is running[/yellow]")
        sys.exit(1)
    
    # Test connection
    headers = {'Authorization': api_key}
    try:
        response = requests.get(f"{mobsf_url}/api/v1/scans", headers=headers, timeout=10)
        if response.status_code == 200:
            console.print(f"[green]✅ Connected to MobSF with API key[/green]")
            return mobsf_url, headers
        else:
            console.print(f"[red]❌ API key test failed: {response.status_code}[/red]")
            sys.exit(1)
    except RequestException as e:
        console.print(f"[red]❌ Cannot connect to MobSF: {e}[/red]")
        sys.exit(1)

def check_scan_exists(mobsf_url, headers, hash_value):
    """Check if scan exists in MobSF"""
    try:
        r = requests.post(f"{mobsf_url}/api/v1/scan_exists", headers=headers, data={'hash': hash_value}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return data.get('exists', False)
        return False
    except RequestException:
        return False

def detect_file_type(path: str) -> str:
    ext = Path(path).suffix.lower()
    return {
        '.apk': 'apk',
        '.ipa': 'ipa',
        '.zip': 'zip',
        '.appx': 'appx'
    }.get(ext)

@click.group()
def cli():
    """MobSF CLI - Auto DB API Key"""
    pass

@cli.command()
@click.argument('file_input', type=click.Path(exists=True))
@click.option('--wait', is_flag=True, help='Wait for scan to complete')
def scan(file_input, wait):
    """Upload and scan a file - Auto API key from DB"""
    mobsf_url, headers = ensure_mobsf_connection()

    file_path = os.path.abspath(file_input)
    if not os.path.exists(file_path):
        console.print(f"[red]Error: File not found: {file_input}[/red]")
        return

    file_type = detect_file_type(file_path)
    if not file_type:
        console.print("[red]Error: Unsupported file type[/red]")
        return

    file_size = os.path.getsize(file_path)
    console.print(f"[dim]File type: {file_type}, Size: {file_size/(1024*1024):.1f}MB[/dim]")

    # Upload
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Uploading file...", total=None)
        
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            
            try:
                r = requests.post(f"{mobsf_url}/api/v1/upload", headers=headers, files=files, timeout=300)
                if r.status_code != 200:
                    console.print(f"[red]Upload failed: {r.text}[/red]")
                    return

                upload_result = r.json()
                if "hash" not in upload_result:
                    console.print(f"[red]Upload failed: No hash in response[/red]")
                    return

                file_hash = upload_result["hash"]
                console.print(f"[green]✓ Upload successful[/green]")
                console.print(f"[dim]File Hash: {file_hash}[/dim]")
                
            except Exception as e:
                console.print(f"[red]Upload error: {str(e)}[/red]")
                return

        # Scan
        progress.add_task(description="Starting scan...", total=None)
        try:
            r = requests.post(
                f"{mobsf_url}/api/v1/scan",
                headers=headers,
                data={'scan_type': file_type, 'hash': file_hash, 're_scan': '0'},
                timeout=30
            )
            if r.status_code != 200:
                console.print(f"[red]Scan failed: {r.text}[/red]")
                return
                
        except requests.exceptions.ReadTimeout:
            console.print("[yellow]⚠ Scan request sent, processing...[/yellow]")
        except Exception as e:
            console.print(f"[red]Scan request error: {str(e)}[/red]")
            return

        if wait:
            console.print("[yellow]⏳ Waiting for scan to complete...[/yellow]")
            max_attempts = 36
            for attempt in range(max_attempts):
                time.sleep(10)
                if check_scan_exists(mobsf_url, headers, file_hash):
                    console.print("[green]✓ Scan completed![/green]")
                    break
                elif attempt == max_attempts - 1:
                    console.print("[yellow]⚠ Scan taking longer than expected[/yellow]")
        else:
            console.print(f"[bold]Scan started! Hash: {file_hash}[/bold]")

@cli.command()
@click.argument('hash')
def permission_analysis(hash):
    """Analyze app permissions - Auto API key from DB"""
    mobsf_url, headers = ensure_mobsf_connection()

    # Check if scan exists
    try:
        r = requests.post(f"{mobsf_url}/api/v1/scan_exists", headers=headers, data={'hash': hash}, timeout=10)
        if r.status_code != 200 or not r.json().get('exists'):
            console.print("[red]Error: Scan not found. Please scan the file first.[/red]")
            return
        
        scan_info = r.json()
        scan_type = scan_info.get('scan_type', '').lower()
        console.print(f"[green]✓ Scan found: {scan_info.get('file_name', 'Unknown')}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error checking scan: {e}[/red]")
        return

    console.print(f"\n[bold cyan]🔐 Permission Analysis for {scan_type.upper()}[/bold cyan]")
    
    # Get manifest or plist data
    if scan_type == 'android':
        endpoint = 'manifest_view'
    elif scan_type in ['ios', 'ipa']:
        endpoint = 'plist_view'
    else:
        console.print(f"[yellow]Permission analysis not supported for {scan_type}[/yellow]")
        return

    try:
        r = requests.post(f"{mobsf_url}/api/v1/{endpoint}", headers=headers, data={'hash': hash}, timeout=10)
        if r.status_code != 200:
            console.print(f"[red]Failed to get data: {r.text}[/red]")
            return

        data = r.json()
        
        if scan_type == 'android':
            permissions = data.get('permissions', {})
            if permissions:
                perm_list = list(permissions.keys()) if isinstance(permissions, dict) else permissions
                
                try:
                    analysis = analyze_android_perms(perm_list)
                    
                    console.print(f"\n[bold]Summary:[/bold]")
                    console.print(f"  Total Permissions: {analysis['total_permissions']}")
                    console.print(f"  Average Risk Score: {analysis['average_risk_score']:.2f}")
                    console.print(f"  Overall Risk: [bold]{analysis['overall_risk_level']}[/bold]")
                    
                    # Show high risk permissions
                    high_risk = analysis['risk_categories'].get('HIGH', []) + analysis['risk_categories'].get('CRITICAL', [])
                    if high_risk:
                        console.print(f"\n[bold red]🚨 High/Critical Risk Permissions:[/bold red]")
                        for perm in high_risk[:5]:
                            console.print(f"  • {perm['permission']} (Score: {perm['risk_score']})")
                            
                except Exception as e:
                    console.print(f"[yellow]Basic analysis: {len(perm_list)} permissions[/yellow]")
                        
        else:  # iOS
            permissions = data.get('permissions', {})
            if permissions:
                try:
                    analysis = analyze_ios_perms(permissions)
                    console.print(f"\n[bold]Summary:[/bold]")
                    console.print(f"  Total Usage Descriptions: {analysis['total_usage_descriptions']}")
                    console.print(f"  Average Risk Score: {analysis['average_risk_score']:.2f}")
                    console.print(f"  Overall Risk: [bold]{analysis['overall_risk_level']}[/bold]")
                except Exception as e:
                    console.print(f"[yellow]Basic analysis: {len(permissions)} usage descriptions[/yellow]")
                        
    except Exception as e:
        console.print(f"[red]Error during permission analysis: {e}[/red]")

@cli.command()
def status():
    """Check MobSF status - Auto API key from DB"""
    mobsf_url, headers = ensure_mobsf_connection()

    try:
        r = requests.get(f"{mobsf_url}/api/v1/scans", headers=headers, timeout=10)
        if r.status_code == 200:
            console.print("[green]✓ MobSF server is running[/green]")
            scans_data = r.json()
            scans = scans_data.get('scans', []) if isinstance(scans_data, dict) else scans_data
            console.print(f"[dim]Recent scans: {len(scans)}[/dim]")
        else:
            console.print(f"[red]✗ MobSF server error: {r.status_code}[/red]")
    except RequestException as e:
        console.print(f"[red]✗ Cannot connect to MobSF: {e}[/red]")

if __name__ == "__main__":
    cli()