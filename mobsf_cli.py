#!/usr/bin/env python3

import os
import sys
import json
import time
import logging
from pathlib import Path
import requests
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich import box

# Import local modules
from api_grabber import grab_api_key, load_config  # Still same function name
from utils.formatters import format_security_score, format_scan_summary

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scan.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
console = Console()

# Load config
CONFIG_PATH = Path(__file__).parent / 'config.json'

def ensure_config():
    """Ensure we have a valid config with session"""
    cfg = load_config()
    if not cfg.get('session_cookie'):
        logger.info('No session cookie in config, attempting to login...')
        session = grab_api_key()  # This now returns session cookie
        if not session:
            logger.error('Could not login to MobSF; aborting')
            sys.exit(1)
        cfg = load_config()
    return cfg

def detect_file_type(path: str) -> str:
    """Detect file type based on extension"""
    ext = Path(path).suffix.lower()
    return {
        '.apk': 'apk',
        '.ipa': 'ipa',
        '.zip': 'zip',
        '.appx': 'appx'
    }.get(ext)

def resolve_file_path(file_input: str) -> str:
    """Resolve file path - supports both relative and absolute paths"""
    if os.path.isabs(file_input):
        return file_input
    
    if os.path.exists(file_input):
        return os.path.abspath(file_input)
    
    # Search in common directories
    search_dirs = [
        '.',
        'app/build/outputs/apk',
        'app/build/outputs/apk/debug',
        'app/build/outputs/apk/release', 
        'build/outputs/apk',
        'platforms/android/app/build/outputs/apk',
        'android/app/build/outputs/apk',
        '../app/build/outputs/apk',
        '~/Downloads',
        '/tmp',
    ]
    
    search_dirs = [os.path.expanduser(d) for d in search_dirs]
    search_dirs = [os.path.abspath(d) for d in search_dirs if os.path.exists(d)]
    
    for search_dir in search_dirs:
        potential_path = os.path.join(search_dir, file_input)
        if os.path.exists(potential_path):
            console.print(f"[dim]Found file at: {potential_path}[/dim]")
            return potential_path
        
        if not file_input.lower().endswith(('.apk', '.ipa', '.appx')):
            potential_path_apk = os.path.join(search_dir, file_input + '.apk')
            if os.path.exists(potential_path_apk):
                console.print(f"[dim]Found file at: {potential_path_apk}[/dim]")
                return potential_path_apk
    
    return file_input

def save_output(data, filename, output_dir="outputs"):
    """Save output to file"""
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)
    
    try:
        if isinstance(data, (dict, list)):
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            with open(filepath, 'wb') as f:
                f.write(data)
        return filepath
    except Exception as e:
        console.print(f"[red]Error saving file: {e}[/red]")
        return None

def check_server_connection(mobsf_url: str) -> bool:
    """Check if MobSF server is running and accessible"""
    try:
        if not mobsf_url.startswith(('http://', 'https://')):
            console.print("[red]Error: Invalid URL format. Must start with http:// or https://[/red]")
            return False
        
        response = requests.get(f"{mobsf_url}/api_docs", timeout=5)
        if response.status_code == 200:
            return True
        else:
            console.print(f"[yellow]Warning: MobSF returned status code {response.status_code}[/yellow]")
            return False
        
    except requests.exceptions.ConnectionError:
        console.print(f"[red]Error: Could not connect to MobSF server at {mobsf_url}[/red]")
        return False
    except requests.exceptions.Timeout:
        console.print("[red]Error: Connection to MobSF server timed out[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Error checking server: {str(e)}[/red]")
        return False

def get_auth_headers(config):
    """Get authentication headers (session cookie)"""
    session_cookie = config.get('session_cookie')
    if session_cookie:
        return {'Cookie': f'sessionid={session_cookie}'}
    return {}

@click.group()
@click.pass_context
def cli(ctx):
    """MobSF CLI - Complete Mobile Security Framework Interface"""
    # Check server connection first
    config = ensure_config()
    mobsf_url = config.get("mobsf_url", "http://localhost:8000")
    
    if not check_server_connection(mobsf_url):
        console.print("[red]Error: Cannot connect to MobSF server. Make sure it's running.[/red]")
        sys.exit(1)
    
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['url'] = mobsf_url

@cli.command()
@click.argument('file_input')
@click.option('--output', '-o', default='json', 
              type=click.Choice(['json', 'pdf', 'all', 'summary']),
              help='Output format')
@click.option('--rescan', is_flag=True, help='Rescan if already exists')
@click.option('--delete', is_flag=True, help='Delete scan after completion')
@click.option('--wait', is_flag=True, help='Wait for scan completion')
@click.pass_context
def scan(ctx, file_input, output, rescan, delete, wait):
    """Scan a mobile application file"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)

    console.print(f"[dim]Looking for file: {file_input}[/dim]")
    
    # Resolve file path
    file_path = resolve_file_path(file_input)
    
    # Validate file exists
    if not os.path.exists(file_path):
        console.print(f"[red]Error: File not found: {file_input}[/red]")
        console.print("[yellow]Searched in common Android project directories[/yellow]")
        return
    
    console.print(f"[green]✓ File found: {file_path}[/green]")
    
    # Validate file size and type
    try:
        file_type = detect_file_type(file_path)
        if not file_type:
            console.print("[red]Error: Unsupported file type[/red]")
            console.print("[yellow]Supported types: .apk, .ipa, .zip, .appx[/yellow]")
            return
        
        file_size = os.path.getsize(file_path)
        max_size = config.get('max_file_size', 500 * 1024 * 1024)
        if file_size > max_size:
            console.print(f"[red]Error: File size exceeds limit of {max_size/(1024*1024):.0f}MB[/red]")
            return
        
        console.print(f"[dim]File type: {file_type}, Size: {file_size/(1024*1024):.1f}MB[/dim]")
        
    except Exception as e:
        console.print(f"[red]Error validating file: {e}[/red]")
        return

    try:
        # Upload file
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Uploading file...", total=None)
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                r = requests.post(
                    f"{mobsf_url}/api/v1/upload",
                    headers=headers,
                    files=files,
                    timeout=config.get('timeout', 300)
                )
                
                if r.status_code != 200:
                    console.print(f"[red]Upload failed: {r.status_code} - {r.text}[/red]")
                    return
                    
                upload_result = r.json()

        if "hash" not in upload_result:
            console.print(f"[red]Upload failed: {upload_result}[/red]")
            return

        file_hash = upload_result["hash"]
        console.print(f"[green]✓ Upload successful[/green]")
        console.print(f"[dim]File Hash: {file_hash}[/dim]")
        console.print(f"[dim]File Type: {file_type}[/dim]")
        
        # Start scan
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Starting scan...", total=None)
            r = requests.post(
                f"{mobsf_url}/api/v1/scan",
                headers=headers,
                data={
                    'scan_type': file_type,
                    'hash': file_hash,
                    're_scan': '1' if rescan else '0'
                },
                timeout=config.get('timeout', 300)
            )
            
            if r.status_code != 200:
                console.print(f"[red]Scan failed: {r.status_code} - {r.text}[/red]")
                return
                
            scan_result = r.json()

        if "error" in scan_result:
            console.print(f"[red]Scan failed: {scan_result['error']}[/red]")
            return

        console.print("[green]✓ Scan started successfully[/green]")

        if wait:
            # Wait for scan completion
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task(description="Scanning in progress...", total=None)
                
                # Poll for results
                max_attempts = 60
                for attempt in range(max_attempts):
                    time.sleep(5)
                    r = requests.get(
                        f"{mobsf_url}/api/v1/report_json",
                        headers=headers,
                        params={'hash': file_hash}
                    )
                    
                    if r.status_code != 200:
                        continue
                        
                    report = r.json()

                    if "error" not in report and report.get("scan_details", {}).get("scan_status") == "SCAN_COMPLETED":
                        progress.update(task, description="Scan completed!")
                        break
                    
                    if attempt == max_attempts - 1:
                        console.print("[yellow]⚠ Scan taking longer than expected[/yellow]")
                        break

        # Get final results and save outputs
        timestamp = int(time.time())
        base_name = f"scan_{os.path.basename(file_path)}_{timestamp}"

        if output in ['json', 'all']:
            r = requests.get(
                f"{mobsf_url}/api/v1/report_json",
                headers=headers,
                params={'hash': file_hash}
            )
            
            if r.status_code == 200:
                json_report = r.json()
                json_file = save_output(json_report, f"{base_name}.json", "outputs/json")
                if json_file:
                    console.print(f"[green]✓ JSON report: {json_file}[/green]")

                if output == 'summary':
                    format_scan_summary(console, json_report)

        if output in ['pdf', 'all']:
            r = requests.get(
                f"{mobsf_url}/api/v1/download_pdf",
                headers=headers,
                params={'hash': file_hash}
            )
            
            if r.status_code == 200:
                pdf_file = save_output(r.content, f"{base_name}.pdf", "outputs/pdf")
                if pdf_file:
                    console.print(f"[green]✓ PDF report: {pdf_file}[/green]")

        # Cleanup if requested
        if delete:
            r = requests.post(
                f"{mobsf_url}/api/v1/delete_scan",
                headers=headers,
                data={'hash': file_hash}
            )
            if r.status_code == 200:
                console.print("[dim]Scan deleted from MobSF[/dim]")

        console.print("[bold green]🎉 Operation completed successfully![/bold green]")

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Network error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

@cli.command()
@click.pass_context
def status(ctx):
    """Check MobSF server status"""
    config = ctx.obj['config']
    headers = get_auth_headers(config)
    
    try:
        r = requests.get(ctx.obj['url'], headers=headers)
        if r.status_code == 200 and "MobSF" in r.text:
            console.print("[green]✓ MobSF server is running[/green]")
            if config.get('session_cookie'):
                console.print("[green]✓ Authenticated with session[/green]")
            else:
                console.print("[yellow]⚠ Not authenticated[/yellow]")
        else:
            console.print("[red]✗ MobSF server is not responding correctly[/red]")
    except Exception:
        console.print("[red]✗ Could not connect to MobSF server[/red]")

if __name__ == "__main__":
    cli()