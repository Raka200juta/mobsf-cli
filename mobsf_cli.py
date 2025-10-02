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
from api_grabber import grab_api_key, load_config
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


def ensure_config():
    """Ensure we have a valid config - always get fresh API key"""
    api_key = grab_api_key()
    if not api_key:
        logger.error('Could not obtain API key; aborting')
        sys.exit(1)
    
    return {
        "mobsf_url": "http://localhost:8000",
        "api_key": api_key,
        "default_output": "json",
        "auto_delete": False,
        "save_reports": True,
        "timeout": None,  # No timeout
        "scan_timeout": 1800,  # 30 minutes for scanning
        "max_file_size": 104857600
    }


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
    """Get authentication headers"""
    api_key = config.get('api_key')
    if api_key:
        return {'Authorization': api_key}
    return {}


def get_report(url, headers, hash_value):
    """Get report from MobSF"""
    try:
        # First check if scan exists and is complete
        scan_check = requests.post(
            f"{url}/api/v1/scan_exists",
            headers=headers,
            data={'hash': hash_value}
        )
        
        if scan_check.status_code != 200:
            console.print("[red]Error: Could not verify scan status[/red]")
            return None
            
        scan_data = scan_check.json()
        if not scan_data.get('exists', False):
            console.print("[red]Error: Scan not found. Please scan the file first.[/red]")
            return None
            
        # Get the report using GET method
        response = requests.get(
            f"{url}/api/v1/report_json",
            headers=headers,
            params={'hash': hash_value}
        )
        
        if response.status_code == 200:
            try:
                return response.json()
            except json.JSONDecodeError:
                console.print("[red]Error: Invalid JSON response from server[/red]")
                return None
        else:
            console.print(f"[red]Error getting report: {response.status_code} - {response.text}[/red]")
            return None
            
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Network error: {str(e)}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        return None


@click.group()
@click.pass_context
def cli(ctx):
    """MobSF CLI - Complete Mobile Security Framework Interface"""
    config = ensure_config()
    mobsf_url = config.get("mobsf_url", "http://localhost:8000")
    
    if not check_server_connection(mobsf_url):
        console.print("[red]Error: Cannot connect to MobSF server. Make sure it's running.[/red]")
        console.print("[yellow]Hint: Run 'docker run -d -p 8000:8000 opensecurity/mobile-security-framework-mobsf' to start MobSF[/yellow]")
        sys.exit(1)
    
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['url'] = mobsf_url


@cli.command()
@click.argument('file_input', type=click.Path(exists=True))
@click.option('--output', '-o', default='json', 
              type=click.Choice(['json', 'pdf', 'all', 'summary']),
              help='Output format')
@click.option('--rescan', is_flag=True, help='Rescan if already exists')
@click.option('--delete', is_flag=True, help='Delete scan after completion')
@click.option('--wait', is_flag=True, help='Wait for scan completion')
@click.option('--timeout', '-t', type=int, help='Scan timeout in seconds (default: 1800)')
@click.pass_context
def scan(ctx, file_input, output, rescan, delete, wait, timeout):
    """Scan a mobile application file"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    # Override scan timeout if provided
    if timeout:
        config['scan_timeout'] = timeout
    
    console.print("[dim]Starting scan process...[/dim]")
    if not os.path.exists(file_input):
        console.print(f"[red]Error: File not found: {file_input}[/red]")
        return

    console.print(f"[dim]Looking for file: {file_input}[/dim]")
    
    file_path = resolve_file_path(file_input)
    
    if not os.path.exists(file_path):
        console.print(f"[red]Error: File not found: {file_input}[/red]")
        console.print("[yellow]Searched in common Android project directories[/yellow]")
        return
    
    console.print(f"[green]✓ File found: {file_path}[/green]")
    
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
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Uploading file...", total=None)
            with open(file_path, 'rb') as f:
                files = {
                    'file': (
                        os.path.basename(file_path),
                        f,
                        'application/octet-stream'
                    )
                }
                try:
                    # Calculate upload timeout based on file size (minimum 5 minutes)
                    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                    upload_timeout = max(300, int(file_size_mb * 10))  # 10 seconds per MB
                    
                    r = requests.post(
                        f"{mobsf_url}/api/v1/upload",
                        headers=headers,
                        files=files,
                        timeout=upload_timeout,  # Dynamic timeout based on file size
                        timeout=config.get('timeout', 300)
                    )
                    
                    if r.status_code != 200:
                        error_msg = r.json().get('error', r.text) if r.text else 'Unknown error'
                        console.print(f"[red]Upload failed: {error_msg}[/red]")
                        return
                        
                except Exception as e:
                    console.print(f"[red]Upload error: {str(e)}[/red]")
                    return
                
                upload_result = r.json()

        if "hash" not in upload_result:
            console.print(f"[red]Upload failed: {upload_result}[/red]")
            return

        file_hash = upload_result["hash"]
        console.print(f"[green]✓ Upload successful[/green]")
        console.print(f"[dim]File Hash: {file_hash}[/dim]")
        console.print(f"[dim]File Type: {file_type}[/dim]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            # Calculate scan timeout based on file size (minimum 10 minutes)
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            scan_timeout = max(600, int(file_size_mb * 20))  # 20 seconds per MB
            
            progress.add_task(
                description=f"Starting scan (timeout: {scan_timeout}s)...", 
                total=None
            )
            
            r = requests.post(
                f"{mobsf_url}/api/v1/scan",
                headers=headers,
                data={
                    'scan_type': file_type,
                    'hash': file_hash,
                    're_scan': '1' if rescan else '0'
                },
                timeout=scan_timeout  # Dynamic timeout based on file size
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
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task(description="Scanning in progress...", total=None)
                
                scan_timeout = config.get('scan_timeout', 1800)  # 30 minutes default
                poll_interval = 10  # Check every 10 seconds
                max_attempts = scan_timeout // poll_interval
                
                for attempt in range(max_attempts):
                    time.sleep(poll_interval)
                    try:
                        r = requests.get(
                            f"{mobsf_url}/api/v1/report_json",
                            headers=headers,
                            params={'hash': file_hash},
                            timeout=30  # 30 seconds for status check
                        )
                        
                        if r.status_code != 200:
                            continue
                            
                        report = r.json()

                        if "error" not in report and report.get("scan_details", {}).get("scan_status") == "SCAN_COMPLETED":
                            break  # Scan completed successfully
                        
                        # If scan is still running, continue polling
                        progress.update(task, description=f"Scanning in progress... (Attempt {attempt + 1}/{max_attempts})")
                        
                    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                        console.print(f"[yellow]Error checking status: {str(e)}. Retrying...[/yellow]")
                        continue
                        progress.update(task, description="Scan completed!")
                        break
                    
                    if attempt == max_attempts - 1:
                        console.print("[yellow]⚠ Scan taking longer than expected[/yellow]")
                        break

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
    """Check MobSF server status and show recent scans"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        r = requests.get(mobsf_url)
        if r.status_code == 200 and "MobSF" in r.text:
            console.print("[green]✓ MobSF server is running[/green]")
            if config.get('api_key'):
                console.print("[green]✓ API key is configured[/green]")
                console.print(f"[dim]API Key: {config['api_key'][:16]}...[/dim]")

                r = requests.get(
                    f"{mobsf_url}/api/v1/scans",
                    headers=headers
                )
                if r.status_code == 200:
                    try:
                        scans_data = r.json()
                        if isinstance(scans_data, dict):
                            scans = scans_data.get('scans', [])
                        elif isinstance(scans_data, list):
                            scans = scans_data
                        else:
                            scans = []

                        if scans:
                            table = Table(title="Recent Scans", box=box.SIMPLE)
                            table.add_column("File Name", style="cyan")
                            table.add_column("Hash", style="blue")
                            table.add_column("Status", style="green")
                            table.add_column("Type", style="yellow")
                            
                            for scan in scans:
                                if isinstance(scan, dict):
                                    table.add_row(
                                        str(scan.get('file_name', 'N/A')),
                                        str(scan.get('hash', 'N/A')),
                                        str(scan.get('status', 'N/A')),
                                        str(scan.get('scan_type', 'N/A'))
                                    )
                                elif isinstance(scan, str):
                                    table.add_row('Unknown', scan, 'N/A', 'N/A')
                            console.print(table)
                        else:
                            console.print("[yellow]No recent scans found[/yellow]")
                    except json.JSONDecodeError:
                        console.print("[yellow]No scan data available[/yellow]")
        else:
            console.print("[red]✗ MobSF server is not responding correctly[/red]")
    except Exception as e:
        console.print(f"[red]✗ Could not connect to MobSF server: {str(e)}[/red]")


@cli.command()
@click.argument('hash')
@click.pass_context
def delete(ctx, hash):
    """Delete a scan by its hash"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        r = requests.post(
            f"{mobsf_url}/api/v1/delete_scan",
            headers=headers,
            data={'hash': hash}
        )
        if r.status_code == 200:
            console.print(f"[green]✓ Scan {hash} deleted successfully[/green]")
        else:
            console.print(f"[red]Failed to delete scan: {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Error deleting scan: {str(e)}[/red]")


@cli.command()
@click.argument('hash')
@click.option('--format', '-f', default='json',
              type=click.Choice(['json', 'pdf']),
              help='Report format')
@click.pass_context
def report(ctx, hash, format):
    """Get a scan report by hash"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        if format == 'json':
            r = requests.get(
                f"{mobsf_url}/api/v1/report_json",
                headers=headers,
                params={'hash': hash}
            )
            if r.status_code == 200:
                report_data = r.json()
                timestamp = int(time.time())
                json_file = save_output(report_data, f"report_{hash}_{timestamp}.json", "outputs/json")
                if json_file:
                    console.print(f"[green]✓ JSON report saved: {json_file}[/green]")
                    format_scan_summary(console, report_data)
            else:
                console.print(f"[red]Failed to get report: {r.text}[/red]")
        
        elif format == 'pdf':
            r = requests.get(
                f"{mobsf_url}/api/v1/download_pdf",
                headers=headers,
                params={'hash': hash}
            )
            if r.status_code == 200:
                timestamp = int(time.time())
                pdf_file = save_output(r.content, f"report_{hash}_{timestamp}.pdf", "outputs/pdf")
                if pdf_file:
                    console.print(f"[green]✓ PDF report saved: {pdf_file}[/green]")
            else:
                console.print(f"[red]Failed to get PDF report: {r.text}[/red]")
                
    except Exception as e:
        console.print(f"[red]Error getting report: {str(e)}[/red]")


@cli.command()
@click.pass_context
def config(ctx):
    """Show current configuration"""
    config = ctx.obj['config']
    
    table = Table(title="MobSF CLI Configuration", box=box.SIMPLE)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    for key, value in config.items():
        if key == 'api_key':
            value = f"{value[:16]}..." if value else "Not configured"
        table.add_row(key, str(value))
    
    console.print(table)


@cli.command()
@click.argument('hash')
@click.pass_context
def network_security(ctx, hash):
    """Analyze network security configuration (Android)"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        r = requests.post(
            f"{mobsf_url}/api/v1/report_json",
            headers=headers,
            data={'hash': hash}
        )
        if r.status_code == 200:
            data = r.json()
            network_data = data.get('network_security', {})
            
            if network_data:
                # Display network security config
                if 'network_security_config' in network_data:
                    console.print("\n[bold cyan]Network Security Configuration:[/bold cyan]")
                    config_data = network_data['network_security_config']
                    for key, value in config_data.items():
                        console.print(f"  • {key}: {value}")
                
                # Display security issues
                if 'security_issues' in network_data:
                    table = Table(title="Security Issues", box=box.SIMPLE)
                    table.add_column("Issue", style="cyan")
                    table.add_column("Severity", style="yellow")
                    table.add_column("Description", style="green")
                    
                    for issue in network_data['security_issues']:
                        severity = issue.get('severity', 'info')
                        severity_color = {
                            'high': '[red]High[/red]',
                            'medium': '[yellow]Medium[/yellow]',
                            'low': '[green]Low[/green]'
                        }.get(severity.lower(), '[blue]Info[/blue]')
                        
                        table.add_row(
                            issue.get('title', 'Unknown'),
                            severity_color,
                            issue.get('description', '')
                        )
                    console.print(table)
            else:
                console.print("[yellow]No network security data available[/yellow]")
                
        else:
            console.print(f"[red]Failed to get network security analysis: {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")


@cli.command()
@click.argument('hash')
@click.pass_context
def cert_analysis(ctx, hash):
    """Analyze certificates and signing"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        r = requests.post(
            f"{mobsf_url}/api/v1/report_json",
            headers=headers,
            data={'hash': hash}
        )
        if r.status_code == 200:
            data = r.json()
            cert_data = data.get('certificate_analysis', {})
            
            if cert_data:
                # Display certificate info
                console.print("\n[bold cyan]Certificate Information:[/bold cyan]")
                
                # Certificate details
                if 'certificate_info' in cert_data:
                    cert_info = cert_data['certificate_info']
                    table = Table(box=box.SIMPLE)
                    table.add_column("Field", style="cyan")
                    table.add_column("Value", style="green")
                    
                    for key, value in cert_info.items():
                        table.add_row(key, str(value))
                    console.print(table)
                
                # Signing analysis
                if 'signing_analysis' in cert_data:
                    console.print("\n[bold yellow]Signing Analysis:[/bold yellow]")
                    for finding in cert_data['signing_analysis']:
                        severity = finding.get('severity', 'info')
                        severity_color = {
                            'high': 'red',
                            'warning': 'yellow',
                            'info': 'blue',
                            'good': 'green'
                        }.get(severity.lower(), 'white')
                        
                        console.print(f"[{severity_color}]• {finding.get('title', '')}[/{severity_color}]")
                        if 'description' in finding:
                            console.print(f"  {finding['description']}")
            else:
                console.print("[yellow]No certificate analysis data available[/yellow]")
                
        else:
            console.print(f"[red]Failed to get certificate analysis: {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")


@cli.command()
@click.argument('hash')
@click.pass_context
def ios_analysis(ctx, hash):
    """Analyze iOS specific security aspects"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        r = requests.post(
            f"{mobsf_url}/api/v1/report_json",
            headers=headers,
            data={'hash': hash}
        )
        if r.status_code == 200:
            data = r.json()
            
            # Check if it's an iOS app
            if 'ios_api' not in data:
                console.print("[yellow]This doesn't appear to be an iOS application.[/yellow]")
                return
            
            # Transport Security
            if 'transport_security' in data:
                console.print("\n[bold cyan]Transport Security Analysis:[/bold cyan]")
                ts_data = data['transport_security']
                
                table = Table(title="Transport Security Settings", box=box.SIMPLE)
                table.add_column("Setting", style="cyan")
                table.add_column("Value", style="yellow")
                table.add_column("Risk", style="red")
                
                for item in ts_data:
                    table.add_row(
                        item.get('setting', 'Unknown'),
                        str(item.get('value', '')),
                        item.get('risk', 'Unknown')
                    )
                console.print(table)
            
            # MachO Analysis
            if 'macho_analysis' in data:
                console.print("\n[bold cyan]MachO Analysis:[/bold cyan]")
                macho_data = data['macho_analysis']
                
                # Architecture info
                if 'arch' in macho_data:
                    console.print(f"Architecture: {macho_data['arch']}")
                
                # Security checks
                if 'security_checks' in macho_data:
                    table = Table(title="Security Checks", box=box.SIMPLE)
                    table.add_column("Check", style="cyan")
                    table.add_column("Status", style="yellow")
                    
                    for check, status in macho_data['security_checks'].items():
                        status_color = '[green]Enabled[/green]' if status else '[red]Disabled[/red]'
                        table.add_row(check, status_color)
                    console.print(table)
            
        else:
            console.print(f"[red]Failed to get iOS analysis: {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")


@cli.command()
@click.argument('hash')
@click.option('--risk-level', '-r', 
              type=click.Choice(['high', 'warning', 'info', 'secure']),
              help='Filter findings by risk level')
@click.pass_context
def security_score(ctx, hash, risk_level):
    """Show security score and summary"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        r = requests.post(
            f"{mobsf_url}/api/v1/report_json",
            headers=headers,
            data={'hash': hash}
        )
        if r.status_code == 200:
            data = r.json()
            
            # Display security score
            if 'security_score' in data:
                score = data['security_score']
                color = 'green' if score >= 80 else 'yellow' if score >= 50 else 'red'
                console.print(f"\n[bold {color}]Security Score: {score}%[/bold {color}]")
            
            # Display findings summary
            if 'findings' in data:
                findings = data['findings']
                
                table = Table(title="Security Findings Summary", box=box.SIMPLE)
                table.add_column("Category", style="cyan")
                table.add_column("Count", style="yellow")
                table.add_column("Details", style="green")
                
                for category, items in findings.items():
                    if risk_level and category.lower() != risk_level.lower():
                        continue
                        
                    count = len(items)
                    details = ", ".join(item.get('title', 'Unknown') for item in items[:3])
                    if count > 3:
                        details += f" ... and {count-3} more"
                    
                    category_color = {
                        'high': '[red]High Risk[/red]',
                        'warning': '[yellow]Warning[/yellow]',
                        'info': '[blue]Info[/blue]',
                        'secure': '[green]Secure[/green]'
                    }.get(category.lower(), category)
                    
                    table.add_row(category_color, str(count), details)
                
                console.print(table)
            else:
                console.print("[yellow]No security findings available[/yellow]")
                
        else:
            console.print(f"[red]Failed to get security score: {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")


@cli.command()
@click.argument('hash')
@click.option('--format', '-f', 
              type=click.Choice(['json', 'pdf']),
              default='json',
              help='Report format (json or pdf)')
@click.pass_context
def report(ctx, hash, format):
    """Get detailed report in JSON or PDF format"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        if format == 'pdf':
            r = requests.get(
                f"{mobsf_url}/api/v1/download_pdf",
                headers=headers,
                params={'hash': hash}
            )
        else:  # json format
            r = requests.get(
                f"{mobsf_url}/api/v1/report_json",
                headers=headers,
                params={'hash': hash}
            )
            
        if r.status_code == 200:
            timestamp = int(time.time())
            if format == 'pdf':
                filename = f"report_{hash}_{timestamp}.pdf"
                filepath = save_output(r.content, filename, "outputs/pdf")
                if filepath:
                    console.print(f"[green]✓ PDF report saved: {filepath}[/green]")
            else:
                try:
                    data = r.json()
                    filename = f"report_{hash}_{timestamp}.json"
                    filepath = save_output(data, filename, "outputs/json")
                    if filepath:
                        console.print(f"[green]✓ JSON report saved: {filepath}[/green]")
                        
                        # Show brief summary
                        if 'security_score' in data:
                            score = data['security_score']
                            color = 'green' if score >= 80 else 'yellow' if score >= 50 else 'red'
                            console.print(f"\n[bold {color}]Security Score: {score}%[/bold {color}]")
                        
                        if 'average_cvss' in data:
                            console.print(f"Average CVSS: {data['average_cvss']}")
                            
                        # Show findings count
                        if 'findings' in data:
                            console.print("\n[bold]Findings Summary:[/bold]")
                            for severity, items in data['findings'].items():
                                count = len(items)
                                if count > 0:
                                    severity_color = {
                                        'high': 'red',
                                        'warning': 'yellow',
                                        'info': 'blue',
                                        'secure': 'green'
                                    }.get(severity.lower(), 'white')
                                    console.print(f"[{severity_color}]{severity}: {count}[/{severity_color}]")
                except json.JSONDecodeError:
                    console.print("[red]Error: Invalid JSON response[/red]")
        else:
            console.print(f"[red]Failed to get report: {r.status_code} - {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")


@cli.command()
@click.argument('hash')
@click.pass_context
def manifest_analysis(ctx, hash):
    """Analyze Android app manifest"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        # First get scan type
        r = requests.post(
            f"{mobsf_url}/api/v1/scan",
            headers=headers,
            data={'hash': hash}
        )
        if r.status_code != 200:
            console.print("[red]Failed to get scan info[/red]")
            return
            
        scan_info = r.json()
        scan_type = scan_info.get('scan_type', '').lower()
        
        # Different endpoint based on app type
        if scan_type == 'android':
            endpoint = 'manifest_view'
        elif scan_type in ['ios', 'ipa']:
            endpoint = 'plist_view'
        else:
            console.print(f"[yellow]Manifest analysis not available for {scan_type} apps[/yellow]")
            return
            
        r = requests.post(
            f"{mobsf_url}/api/v1/{endpoint}",
            headers=headers,
            data={'hash': hash}
        )
        if r.status_code == 200:
            data = r.json()
            
            # Ekstrak data manifest dari report lengkap
            manifest_data = data.get('androidmanifest', {})
            
            if manifest_data:
                # Show manifest info
                console.print("\n[bold cyan]Manifest Analysis:[/bold cyan]")
                
                # Basic manifest information
                if 'manifest' in manifest_data:
                    console.print("\n[bold yellow]Basic Manifest Info:[/bold yellow]")
                    table = Table(box=box.SIMPLE)
                    table.add_column("Property", style="cyan")
                    table.add_column("Value", style="green")
                    
                    manifest_info = manifest_data['manifest']
                    for key, value in manifest_info.items():
                        if key not in ['activities', 'services', 'receivers', 'providers', 'permissions']:
                            table.add_row(str(key), str(value))
                    console.print(table)
                
                # Permissions
                if 'permissions' in manifest_data:
                    permissions = manifest_data['permissions']
                    console.print(f"\n[bold yellow]Permissions ({len(permissions)}):[/bold yellow]")
                    
                    # Group by permission category
                    dangerous_perms = []
                    normal_perms = []
                    signature_perms = []
                    
                    for perm in permissions:
                        perm_name = perm.get('name', 'Unknown')
                        if any(dangerous in perm_name.lower() for dangerous in 
                              ['camera', 'location', 'contacts', 'sms', 'phone', 'storage', 
                               'microphone', 'camera', 'call_log']):
                            dangerous_perms.append(perm_name)
                        elif 'signature' in perm_name.lower():
                            signature_perms.append(perm_name)
                        else:
                            normal_perms.append(perm_name)
                    
                    if dangerous_perms:
                        console.print("\n[red]⚠ Dangerous Permissions:[/red]")
                        for perm in dangerous_perms:
                            console.print(f"  • {perm}")
                    
                    if signature_perms:
                        console.print("\n[yellow]Signature Permissions:[/yellow]")
                        for perm in signature_perms:
                            console.print(f"  • {perm}")
                    
                    if normal_perms:
                        console.print("\n[green]Normal Permissions:[/green]")
                        for perm in normal_perms[:10]:  # Show first 10
                            console.print(f"  • {perm}")
                        if len(normal_perms) > 10:
                            console.print(f"  ... and {len(normal_perms) - 10} more")
                
                # Components
                components_to_check = ['activities', 'services', 'receivers', 'providers']
                for component in components_to_check:
                    if component in manifest_data:
                        comp_list = manifest_data[component]
                        if comp_list:
                            console.print(f"\n[bold yellow]{component.title()} ({len(comp_list)}):[/bold yellow]")
                            for comp in comp_list[:5]:  # Show first 5
                                console.print(f"  • {comp}")
                            if len(comp_list) > 5:
                                console.print(f"  ... and {len(comp_list) - 5} more")
                
            else:
                console.print("[yellow]No manifest analysis data available[/yellow]")
        else:
            console.print(f"[red]Failed to get manifest analysis: {r.status_code} - {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")


@cli.command()
@click.argument('hash')
@click.pass_context
def code_analysis(ctx, hash):
    """Analyze application code"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        # First get scan type
        r = requests.post(
            f"{mobsf_url}/api/v1/scan",
            headers=headers,
            data={'hash': hash}
        )
        if r.status_code != 200:
            console.print("[red]Failed to get scan info[/red]")
            return
            
        scan_info = r.json()
        scan_type = scan_info.get('scan_type', '').lower()
        
        # Different endpoint based on app type
        r = requests.post(
            f"{mobsf_url}/api/v1/view_source",
            headers=headers,
            data={'hash': hash, 'type': scan_type, 'file': 'json'}
        )
        if r.status_code == 200:
            data = r.json()
            code_data = data.get('code_analysis', {})
            
            if code_data:
                # Group findings by severity
                findings = {'high': [], 'warning': [], 'info': [], 'secure': []}
                for finding in code_data:
                    severity = finding.get('severity', 'info').lower()
                    findings[severity].append(finding)
                
                # Display findings by severity
                for severity, items in findings.items():
                    if items:
                        severity_color = {
                            'high': 'red',
                            'warning': 'yellow',
                            'info': 'blue',
                            'secure': 'green'
                        }[severity]
                        
                        console.print(f"\n[bold {severity_color}]{severity.upper()} Risk Findings:[/bold {severity_color}]")
                        table = Table(box=box.SIMPLE)
                        table.add_column("Title", style="cyan")
                        table.add_column("File", style="yellow")
                        table.add_column("Description", style=severity_color)
                        
                        for item in items:
                            table.add_row(
                                item.get('title', 'Unknown'),
                                item.get('file', ''),
                                item.get('description', '')
                            )
                        console.print(table)
            else:
                console.print("[yellow]No code analysis data available[/yellow]")
        else:
            console.print(f"[red]Failed to get code analysis: {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")


@cli.command()
@click.argument('hash')
@click.pass_context
def binary_analysis(ctx, hash):
    """Analyze app binary and libraries"""
    config = ctx.obj['config']
    mobsf_url = ctx.obj['url']
    headers = get_auth_headers(config)
    
    try:
        # First get scan type
        r = requests.post(
            f"{mobsf_url}/api/v1/scan",
            headers=headers,
            data={'hash': hash}
        )
        if r.status_code != 200:
            console.print("[red]Failed to get scan info[/red]")
            return
            
        scan_info = r.json()
        scan_type = scan_info.get('scan_type', '').lower()
        file_name = scan_info.get('file_name', '')
        
        # Different endpoint based on app type
        if scan_type == 'android':
            # For Android, use view_binary endpoint
            r = requests.post(
                f"{mobsf_url}/api/v1/view_binary",
                headers=headers,
                data={
                    'hash': hash,
                    'type': scan_type,
                    'file': file_name
                }
            )
        elif scan_type in ['ios', 'ipa']:
            # For iOS, use binary endpoint
            r = requests.post(
                f"{mobsf_url}/api/v1/ios_binary",
                headers=headers,
                data={
                    'hash': hash,
                    'type': scan_type,
                    'file': file_name
                }
            )
        else:
            console.print(f"[yellow]Binary analysis not available for {scan_type} apps[/yellow]")
            return
        if r.status_code == 200:
            data = r.json()
            binary_data = data.get('binary_analysis', {})
            
            if binary_data:
                # Show binary info
                console.print("\n[bold cyan]Binary Analysis:[/bold cyan]")
                table = Table(box=box.SIMPLE)
                table.add_column("Check", style="cyan")
                table.add_column("Status", style="yellow")
                table.add_column("Info", style="green")
                
                for check, info in binary_data.items():
                    status = info.get('status', 'unknown')
                    status_color = {
                        'high': '[red]Vulnerable[/red]',
                        'warning': '[yellow]Warning[/yellow]',
                        'secure': '[green]Secure[/green]',
                        'info': '[blue]Info[/blue]'
                    }.get(status.lower(), status)
                    
                    table.add_row(
                        check,
                        status_color,
                        info.get('description', '')
                    )
                console.print(table)
                
                # Show libraries if available
                if 'libraries' in data:
                    console.print("\n[bold cyan]Libraries:[/bold cyan]")
                    for lib in data['libraries']:
                        console.print(f"• {lib}")
            else:
                console.print("[yellow]No binary analysis data available[/yellow]")
        else:
            console.print(f"[red]Failed to get binary analysis: {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")


if __name__ == "__main__":
    cli()