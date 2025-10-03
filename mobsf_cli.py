#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MobSF Auto CLI
Ambil API key dari input user (karena database tidak menyimpan), lalu jalankan permission & behavior analysis.
"""

import json
import sys
import time
import click
import requests
from pathlib import Path
from requests.exceptions import RequestException
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# === CONFIG ===
CONFIG_FILE = Path.home() / '.mobsf_cli.json'
ENDPOINTS_FILE = Path("endpoints.json")  # File endpoint

def load_endpoints():
    """Load endpoints from endpoints.json"""
    if not ENDPOINTS_FILE.exists():
        console.print(f"[red]File {ENDPOINTS_FILE} tidak ditemukan.[/red]")
        sys.exit(1)

    try:
        with open(ENDPOINTS_FILE, "r") as f:
            endpoints = json.load(f)
        return endpoints
    except json.JSONDecodeError:
        console.print(f"[red]File {ENDPOINTS_FILE} bukan JSON valid.[/red]")
        sys.exit(1)

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def get_auth_headers(config):
    api_key = config.get('api_key')
    if not api_key:
        console.print("[red]API key not found. Please configure it first.[/red]")
        sys.exit(1)
    return {'Authorization': api_key}

def get_api_key_from_user():
    """Ambil API key dari input user"""
    console.print("[bold cyan]🔧 Setting up MobSF API key...[/bold cyan]")
    console.print("[yellow]Database tidak menyimpan API key.[/yellow]")
    console.print(f"[blue]Silakan buka: http://127.0.0.1:8000/api_docs[/blue]")
    console.print(f"[blue]Login dengan user: mobsf, password: mobsf (default)[/blue]")
    console.print(f"[blue]Lalu copy API key dari halaman tersebut.[/blue]")
    api_key = input("\nMasukkan API key: ").strip()
    if not api_key:
        console.print("[red]API key kosong, keluar.[/red]")
        sys.exit(1)
    return api_key

def test_api_key(mobsf_url, api_key):
    """Test apakah API key valid"""
    headers = {'Authorization': api_key}
    endpoints = load_endpoints()
    try:
        # Ganti ke endpoint yang tidak perlu parameter
        endpoint = endpoints['api']['scans']
        r = requests.post(f"{mobsf_url}{endpoint}", headers=headers, timeout=10)
        if r.status_code == 200:
            console.print("[green]✓ API key valid[/green]")
            return True
        elif r.status_code == 405:
            # Coba method GET
            r_get = requests.get(f"{mobsf_url}{endpoint}", headers=headers, timeout=10)
            if r_get.status_code == 200:
                console.print("[green]✓ API key valid[/green]")
                return True
            else:
                console.print(f"[red]✗ API key tidak valid (GET: HTTP {r_get.status_code})[/red]")
                return False
        else:
            console.print(f"[red]✗ API key tidak valid (HTTP {r.status_code})[/red]")
            return False
    except RequestException as e:
        console.print(f"[red]✗ Error saat test API key: {e}[/red]")
        return False

def detect_file_type(file_path):
    """Deteksi tipe file berdasarkan ekstensi"""
    path = Path(file_path)
    ext = path.suffix.lower()
    supported_types = {
        '.apk': 'apk',
        '.ipa': 'ipa',
        '.zip': 'zip',
        '.appx': 'appx'
    }
    return supported_types.get(ext, None)

def validate_file(file_path):
    """Validasi file sebelum upload"""
    if not Path(file_path).exists():
        console.print(f"[red]File tidak ditemukan: {file_path}[/red]")
        return False

    file_type = detect_file_type(file_path)
    if not file_type:
        console.print(f"[red]Format file tidak didukung: {file_path}[/red]")
        console.print(f"[yellow]Format yang didukung: .apk, .ipa, .zip, .appx[/yellow]")
        return False

    # Cek ukuran file (opsional, bisa disesuaikan)
    file_size = Path(file_path).stat().st_size
    max_size = 500 * 1024 * 1024  # 500MB
    if file_size > max_size:
        console.print(f"[red]File terlalu besar: {file_size / (1024**2):.2f} MB (max: 500 MB)[/red]")
        return False

    return True

# === API FUNCTIONS ===
def check_scan_exists(mobsf_url, headers, hash_value, max_retries=3, delay=5):
    console.print(f"[dim]Checking scan for hash: {hash_value}[/dim]")
    endpoints = load_endpoints()
    for attempt in range(max_retries):
        try:
            r = requests.post(f"{mobsf_url}{endpoints['api']['report_json']}",
                             headers=headers, data={'hash': hash_value}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data and not data.get('error'):
                    console.print(f"[green]✓ Scan found![/green]")
                    scan_type = data.get('app_type', '').lower()
                    original_scan_type = data.get('original_scan_type', scan_type)
                    return {
                        'exists': True,
                        'scan_type': scan_type,
                        'original_scan_type': original_scan_type,
                        'file_name': data.get('file_name', ''),
                    }
            console.print(f"[yellow]⚠ Scan not found (attempt {attempt + 1}/{max_retries})[/yellow]")
            time.sleep(delay)
        except RequestException as e:
            console.print(f"[red]Request error: {e}[/red]")
            time.sleep(delay)
    console.print("[red]✗ Scan not found after all retries[/red]")
    return None

# === COMMAND: UPLOAD & SCAN ===
@click.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--wait', is_flag=True, help='Wait for scan to complete')
@click.pass_context
def scan(ctx, file_path, wait):
    """Upload and scan a file"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    endpoints = load_endpoints()

    console.print("[bold cyan]🚀 Starting Scan...[/bold cyan]")

    # Validasi file
    if not validate_file(file_path):
        return

    # Upload
    console.print("[bold]📦 Uploading file...[/bold]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Uploading...", total=None)
        try:
            with open(file_path, 'rb') as f:
                r = requests.post(f"{mobsf_url}{endpoints['api']['upload']}",
                                 files={'file': f}, headers=headers, timeout=30)
            if r.status_code != 200:
                console.print(f"[red]Upload failed: {r.text}[/red]")
                return
            upload_result = r.json()
            if "hash" not in upload_result:
                console.print(f"[red]Upload failed: No hash in response[/red]")
                return
            file_hash = upload_result["hash"]
            file_type = upload_result.get("scan_type", "unknown")
            console.print(f"[green]✓ Upload successful[/green]")
            console.print(f"[dim]File Hash: {file_hash}[/dim]")
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]Upload error: {str(e)}[/red]")
            return

    # Scan
    try:
        r = requests.post(f"{mobsf_url}{endpoints['api']['scan']}",
                         headers=headers,
                         data={'scan_type': file_type, 'hash': file_hash, 're_scan': '0'},
                         timeout=30)
        if r.status_code != 200:
            console.print(f"[red]Scan failed: {r.text}[/red]")
            return
    except requests.exceptions.ReadTimeout:
        console.print("[yellow]⚠ Scan request sent, processing...[/yellow]")
    except Exception as e:
        console.print(f"[red]Scan request error: {str(e)}[/red]")
        return

    # Wait for scan if requested
    if wait:
        console.print("[yellow]⏳ Waiting for scan to complete...[/yellow]")
        max_attempts = 180
        scan_completed = False
        for attempt in range(max_attempts):
            time.sleep(10)
            try:
                r_check = requests.post(f"{mobsf_url}{endpoints['api']['report_json']}",
                                       headers=headers, data={'hash': file_hash}, timeout=10)
                if r_check.status_code == 200:
                    report_data = r_check.json()
                    if report_data and not report_data.get('error'):
                        scan_completed = True
                        console.print("[green]✓ Scan completed![/green]")
                        break
                if attempt % 3 == 0:  # Setiap 30 detik
                    console.print(f"[dim]⏰ Still scanning... ({attempt * 10} seconds elapsed)[/dim]")
            except RequestException as e:
                if attempt % 3 == 0:
                    console.print(f"[dim]⚠ Check report failed: {e}[/dim]")

        if not scan_completed:
            console.print("[yellow]⚠ Scan taking longer than expected, you can check later with the hash[/yellow]")
            console.print(f"[yellow]Hash: {file_hash}[/yellow]")
            return

        # Run permission and behavior analysis
        console.print("[bold]🔐 Running Permission Analysis...[/bold]")
        ctx.invoke(permission_analysis, hash=file_hash, output='table', wait=False)

        console.print("[bold]🔍 Running Behavior Analysis...[/bold]")
        ctx.invoke(behavior_analysis, hash=file_hash, output='table', wait=False)

    console.print("[bold green]✅ Scan completed![/bold green]")
    console.print(f"[bold]Hash: {file_hash}[/bold]")

# === COMMAND: SETUP (ambil API key dari user dan simpan ke config) ===
@click.command()
@click.option('--url', default='http://127.0.0.1:8000', help='MobSF URL')
def setup(url):
    """Setup API key dari input user"""
    api_key = get_api_key_from_user()

    if not test_api_key(url, api_key):
        console.print("[red]API key tidak valid, keluar.[/red]")
        sys.exit(1)

    config = {
        'api_key': api_key,
        'url': url
    }
    save_config(config)
    console.print("[bold green]✅ Setup selesai![/bold green]")

# === COMMAND: PERMISSION ANALYSIS ===
@click.command()
@click.argument('hash')
@click.option('--output', '-o', type=click.Choice(['json', 'table']), default='table', help='Output format')
@click.option('--wait', is_flag=True, help='Wait for scan to complete')
@click.pass_context
def permission_analysis(ctx, hash, output, wait):
    """Analyze app permissions and their risks (Android/iOS)"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    endpoints = load_endpoints()

    scan_info = check_scan_exists(mobsf_url, headers, hash)
    if not scan_info:
        error_result = {
            'status': 'error',
            'message': 'Scan not found. Please scan the file first.',
            'hash': hash,
            'timestamp': time.time()
        }
        if output in ['json', 'full']:
            console.print(json.dumps(error_result, indent=2))
        else:
            console.print("[red]Error: Scan not found. Please scan the file first.[/red]")
        return

    scan_type = scan_info.get('scan_type', '').lower()
    original_scan_type = scan_info.get('original_scan_type', '')

    console.print(f"[dim]Scan type: {scan_type} (original: {original_scan_type})[/dim]")

    # === AMBIL DATA DARI endpoint yang benar ===
    try:
        if scan_type == 'android':
            # Gunakan endpoint manifest_view untuk Android dari JSON
            endpoint = endpoints['views']['android']['manifest_view'].format(hash=hash)
            console.print(f"[dim]Using Android endpoint: {endpoint}[/dim]")
            r = requests.get(f"{mobsf_url}{endpoint}", headers=headers, timeout=10)
            if r.status_code == 200:
                # Cek apakah response berupa HTML atau JSON
                content_type = r.headers.get('content-type', '')
                if 'text/html' in content_type:
                    # Parse HTML untuk ambil permissions
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(r.text, 'html.parser')
                    # Cari elemen yang menyimpan permissions
                    permissions = []
                    for perm in soup.find_all('span', class_='permission'):
                        permissions.append(perm.text.strip())
                    if not permissions:
                        # Jika tidak ditemukan, coba ambil dari script
                        script_tag = soup.find('script', string=lambda t: t and 'permissions' in t)
                        if script_tag:
                            import re
                            perms_match = re.findall(r'"permissions":\s*\[(.*?)\]', script_tag.string)
                            if perms_match:
                                perms_str = perms_match[0]
                                permissions = [p.strip().strip('"') for p in perms_str.split(',')]
                else:
                    # Jika bukan HTML, coba parse sebagai JSON
                    data = r.json()
                    permissions = data.get('permissions', [])
            else:
                console.print(f"[yellow]⚠ Primary endpoint failed (HTTP {r.status_code}), trying fallback...[/yellow]")
                # Fallback ke report_json
                r = requests.post(f"{mobsf_url}{endpoints['api']['report_json']}", headers=headers, data={'hash': hash}, timeout=10)
                if r.status_code != 200:
                    error_result = {
                        'status': 'error',
                        'message': f'Failed to get manifest data: {r.text}',
                        'status_code': r.status_code,
                        'hash': hash,
                        'timestamp': time.time()
                    }
                    if output in ['json', 'full']:
                        console.print(json.dumps(error_result, indent=2))
                    else:
                        console.print(f"[red]Failed to get manifest  {r.text}[/red]")
                    return
                data = r.json()
                manifest_data = data.get('android_manifest', {})
                permissions = manifest_data.get('permissions', [])
                # Fallback: ambil dari top-level jika tidak ada di manifest
                if not permissions:
                    permissions = data.get('permissions', [])
        elif scan_type == 'ios':
            # Gunakan endpoint ios_view_report untuk iOS dari JSON
            endpoint = endpoints['views']['ios']['ios_view_report'].format(bundle_id=hash)
            console.print(f"[dim]Using iOS endpoint: {endpoint}[/dim]")
            r = requests.get(f"{mobsf_url}{endpoint}", headers=headers, timeout=10)
            if r.status_code == 200:
                # Cek apakah response berupa HTML atau JSON
                content_type = r.headers.get('content-type', '')
                if 'text/html' in content_type:
                    # Parse HTML untuk ambil permissions
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(r.text, 'html.parser')
                    # Cari elemen yang menyimpan permissions
                    permissions = {}
                    for perm in soup.find_all('span', class_='permission'):
                        perm_name = perm.text.strip()
                        perm_desc = perm.find_next_sibling('div', class_='description')
                        perm_desc_text = perm_desc.text.strip() if perm_desc else 'N/A'
                        permissions[perm_name] = {'usage_description': perm_desc_text}
                else:
                    # Jika bukan HTML, coba parse sebagai JSON
                    data = r.json()
                    permissions = data.get('permissions', {})
            else:
                console.print(f"[yellow]⚠ Primary endpoint failed (HTTP {r.status_code}), trying fallback...[/yellow]")
                # Fallback ke report_json
                r = requests.post(f"{mobsf_url}{endpoints['api']['report_json']}", headers=headers, data={'hash': hash}, timeout=10)
                if r.status_code != 200:
                    error_result = {
                        'status': 'error',
                        'message': f'Failed to get manifest data: {r.text}',
                        'status_code': r.status_code,
                        'hash': hash,
                        'timestamp': time.time()
                    }
                    if output in ['json', 'full']:
                        console.print(json.dumps(error_result, indent=2))
                    else:
                        console.print(f"[red]Failed to get manifest  {r.text}[/red]")
                    return
                data = r.json()
                plist_data = data.get('plist_analysis', {})
                permissions = plist_data.get('permissions', {})
        else:
            permissions = {}

    except Exception as e:
        error_result = {
            'status': 'error',
            'message': f'Failed to parse response  {e}',
            'hash': hash,
            'timestamp': time.time()
        }
        if output in ['json', 'full']:
            console.print(json.dumps(error_result, indent=2))
        else:
            console.print(f"[red]Failed to parse response  {e}[/red]")
        return

    # === ANALYSIS ===
    if scan_type == 'android':
        if permissions:
            if output == 'json':
                result = {
                    'status': 'success',
                    'hash': hash,
                    'scan_type': scan_type,
                    'permissions': permissions,
                    'count': len(permissions),
                    'timestamp': time.time()
                }
                console.print(json.dumps(result, indent=2))
            else:
                console.print("[bold cyan]🔐 Android Permission Analysis[/bold cyan]")
                for perm in permissions:
                    console.print(f" • {perm}")
                console.print(f"[bold]Total Permissions: {len(permissions)}[/bold]")
        else:
            console.print("[yellow]No permissions found in manifest.[/yellow]")

    elif scan_type == 'ios':
        if permissions:
            if output == 'json':
                result = {
                    'status': 'success',
                    'hash': hash,
                    'scan_type': scan_type,
                    'permissions': permissions,
                    'count': len(permissions),
                    'timestamp': time.time()
                }
                console.print(json.dumps(result, indent=2))
            else:
                console.print("[bold cyan]🔐 iOS Permission Analysis[/bold cyan]")
                console.print(f"Total Usage Descriptions: {len(permissions)}")
                for desc, info in permissions.items():
                    console.print(f" • {desc}: {info.get('usage_description', 'N/A')}")
        else:
            console.print("[yellow]No permissions found in plist.[/yellow]")

# === COMMAND: BEHAVIOR ANALYSIS ===
@click.command()
@click.argument('hash')
@click.option('--output', '-o', type=click.Choice(['json', 'table']), default='table', help='Output format')
@click.option('--wait', is_flag=True, help='Wait for scan to complete')
@click.pass_context
def behavior_analysis(ctx, hash, output, wait):
    """Analyze app behavior (trackers, malware, APIs)"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    endpoints = load_endpoints()

    scan_info = check_scan_exists(mobsf_url, headers, hash)
    if not scan_info:
        error_result = {
            'status': 'error',
            'message': 'Scan not found. Please scan the file first.',
            'hash': hash,
            'timestamp': time.time()
        }
        if output == 'json':
            console.print(json.dumps(error_result, indent=2))
        else:
            console.print("[red]Error: Scan not found. Please scan the file first.[/red]")
        return

    scan_type = scan_info.get('scan_type', '').lower()
    original_scan_type = scan_info.get('original_scan_type', '')
    console.print(f"[dim]Scan type: {scan_type} (original: {original_scan_type})[/dim]")

    # Supported platforms
    supported_platforms = ['android', 'ios']
    if scan_type not in supported_platforms:
        error_result = {
            'status': 'error',
            'message': f'Behavior analysis not supported for {original_scan_type}',
            'scan_type': scan_type,
            'original_scan_type': original_scan_type,
            'supported_platforms': supported_platforms,
            'timestamp': time.time()
        }
        if output == 'json':
            console.print(json.dumps(error_result, indent=2))
        else:
            console.print(f"[yellow]Behavior analysis not supported for {original_scan_type}[/yellow]")
            console.print(f"[dim]Supported platforms: {', '.join(supported_platforms)}[/dim]")
        return

    # Try to get behavior from custom endpoint first
    try:
        r = requests.post(f"{mobsf_url}{endpoints['api']['behavior']}", headers=headers, data={'hash': hash}, timeout=10)
        if r.status_code != 200:
            console.print(f"[yellow]⚠ Custom behavior endpoint failed, using report_json...[/yellow]")
            # Fallback to report_json
            r = requests.post(f"{mobsf_url}{endpoints['api']['report_json']}", headers=headers, data={'hash': hash}, timeout=10)
            if r.status_code != 200:
                error_result = {
                    'status': 'error',
                    'message': f'Failed to get behavior  {r.text}',
                    'status_code': r.status_code,
                    'hash': hash,
                    'timestamp': time.time()
                }
                if output == 'json':
                    console.print(json.dumps(error_result, indent=2))
                else:
                    console.print(f"[red]Failed to get behavior  {r.text}[/red]")
                return
            data = r.json()
            # Extract behavior from report_json
            behavior_data = {
                'trackers': data.get('trackers', []),
                'malware_patterns': data.get('malware_features', []),
                'urls': data.get('urls', []),
                'android_api': data.get('android_api', []),
                'permissions': data.get('permissions', []),
                'code_analysis': data.get('code_analysis', {}),
                'network_security': data.get('network_security', {}),
            }
        else:
            behavior_data = r.json()

    except RequestException as e:
        error_result = {
            'status': 'error',
            'message': f'Failed to get behavior  {e}',
            'hash': hash,
            'timestamp': time.time()
        }
        if output == 'json':
            console.print(json.dumps(error_result, indent=2))
        else:
            console.print(f"[red]Failed to get behavior  {e}[/red]")
        return

    # Format hasil untuk output JSON
    if output == 'json':
        result = {
            'status': 'success',
            'hash': hash,
            'scan_type': scan_type,
            'behavior_analysis': behavior_data,
            'timestamp': time.time()
        }
        console.print(json.dumps(result, indent=2))
    else:
        # Output table
        console.print("[bold cyan]🔍 Behavior Analysis Results[/bold cyan]")
        console.print(f" • Trackers: {len(behavior_data.get('trackers', []))}")
        console.print(f" • Malware Patterns: {len(behavior_data.get('malware_patterns', []))}")
        console.print(f" • Dangerous APIs: {len(behavior_data.get('android_api', []))}")
        console.print(f" • URLs: {len(behavior_data.get('urls', []))}")

        # Risk assessment
        total_findings = (
            len(behavior_data.get('trackers', [])) +
            len(behavior_data.get('malware_patterns', [])) +
            len(behavior_data.get('android_api', []))
        )
        if total_findings == 0:
            risk_level = "LOW"
            risk_color = "green"
        elif total_findings <= 3:
            risk_level = "MEDIUM"
            risk_color = "yellow"
        elif total_findings <= 6:
            risk_level = "HIGH"
            risk_color = "orange"
        else:
            risk_level = "CRITICAL"
            risk_color = "red"

        console.print(f" • Overall Risk: [{risk_color}]{risk_level}[/{risk_color}]")

# === MAIN CLI ===
@click.group()
@click.option('--url', default='http://127.0.0.1:8000', help='MobSF URL')
@click.option('--api-key', help='MobSF API Key')
@click.pass_context
def cli(ctx, url, api_key):
    """MobSF Auto CLI for permission and behavior analysis."""
    config = load_config()
    if api_key:
        config['api_key'] = api_key
        save_config(config)

    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['url'] = url

# Register commands
cli.add_command(setup)
cli.add_command(scan)
cli.add_command(permission_analysis)
cli.add_command(behavior_analysis)

if __name__ == "__main__":
    cli()