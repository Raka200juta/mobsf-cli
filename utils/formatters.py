#!/usr/bin/env python3
"""
Formatting utilities for MobSF CLI output
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from typing import Dict, List, Any, Optional

def format_security_score(score: int) -> Text:
    """
    Format security score with appropriate color
    
    Args:
        score: Security score (0-100)
        
    Returns:
        Rich Text object with colored score
    """
    if score >= 80:
        return Text(str(score), style="bold green")
    elif score >= 60:
        return Text(str(score), style="bold yellow")
    else:
        return Text(str(score), style="bold red")

def format_severity(severity: str) -> Text:
    """
    Format severity level with color
    
    Args:
        severity: Severity level (high, warning, info, etc.)
        
    Returns:
        Rich Text object with colored severity
    """
    severity = severity.lower()
    if severity in ['high', 'critical', 'error']:
        return Text(severity.upper(), style="bold red")
    elif severity in ['medium', 'warning']:
        return Text(severity.upper(), style="bold yellow")
    elif severity in ['low', 'info']:
        return Text(severity.upper(), style="bold blue")
    else:
        return Text(severity.upper(), style="bold white")

def format_scan_summary(console: Console, scan_data: Dict[str, Any]) -> None:
    """
    Format and display comprehensive scan summary
    
    Args:
        console: Rich Console instance
        scan_data: Scan results data
    """
    # Main application info
    main_table = Table(box=box.ROUNDED, show_header=False, title="Application Information")
    main_table.add_column("Property", style="cyan", width=20)
    main_table.add_column("Value", style="white")
    
    scan_details = scan_data.get('scan_details', {})
    app_name = scan_details.get('app_name', 'N/A')
    package_name = scan_details.get('package_name', 'N/A')
    version_name = scan_details.get('version_name', 'N/A')
    version_code = scan_details.get('version_code', 'N/A')
    file_size = scan_details.get('size', 'N/A')
    
    main_table.add_row("App Name", app_name)
    main_table.add_row("Package Name", package_name)
    main_table.add_row("Version", f"{version_name} ({version_code})" if version_code != 'N/A' else version_name)
    main_table.add_row("File Size", file_size)
    main_table.add_row("MD5", scan_details.get('md5', 'N/A'))
    main_table.add_row("SHA1", scan_details.get('sha1', 'N/A'))
    main_table.add_row("SHA256", scan_details.get('sha256', 'N/A'))
    
    # Security score
    security_score = scan_data.get('security_score', 0)
    main_table.add_row("Security Score", format_security_score(security_score))
    
    console.print(Panel(main_table, title="📱 Scan Summary", title_align="left"))
    
    # Security findings summary
    format_findings_table(console, scan_data)
    
    # Permissions summary
    format_permissions_table(console, scan_data)
    
    # Code issues summary
    format_code_issues(console, scan_data)

def format_findings_table(console: Console, scan_data: Dict[str, Any]) -> None:
    """
    Format security findings table
    
    Args:
        console: Rich Console instance
        scan_data: Scan results data
    """
    code_analysis = scan_data.get('code_analysis', {})
    findings = code_analysis.get('findings', {})
    
    if not findings:
        return
    
    findings_table = Table(box=box.SIMPLE, title="Security Findings Summary")
    findings_table.add_column("Severity", style="bold", width=12)
    findings_table.add_column("Count", style="white", width=8)
    findings_table.add_column("Description", style="dim")
    
    severity_order = ['high', 'warning', 'info', 'secure']
    total_findings = 0
    
    for severity in severity_order:
        if severity in findings:
            count = findings[severity]
            total_findings += count
            
            if severity == 'high':
                desc = "Critical security issues that need immediate attention"
            elif severity == 'warning':
                desc = "Potential security concerns that should be reviewed"
            elif severity == 'info':
                desc = "Informational findings and best practices"
            elif severity == 'secure':
                desc = "Positive security indicators"
            else:
                desc = "Security findings"
            
            findings_table.add_row(
                format_severity(severity),
                str(count),
                desc
            )
    
    if total_findings > 0:
        console.print(Panel(findings_table, title="🔍 Security Findings", title_align="left"))

def format_permissions_table(console: Console, scan_data: Dict[str, Any]) -> None:
    """
    Format permissions table
    
    Args:
        console: Rich Console instance
        scan_data: Scan results data
    """
    permissions = scan_data.get('permissions', [])
    
    if not permissions:
        return
    
    # Count by status
    status_count = {}
    for perm in permissions:
        status = perm.get('status', 'unknown')
        status_count[status] = status_count.get(status, 0) + 1
    
    perm_table = Table(box=box.SIMPLE, title="Permissions Summary")
    perm_table.add_column("Status", style="bold", width=12)
    perm_table.add_column("Count", style="white", width=8)
    perm_table.add_column("Risk Level", style="dim")
    
    status_mapping = {
        'dangerous': ('DANGEROUS', 'bold red', 'High risk - requires user consent'),
        'normal': ('NORMAL', 'bold yellow', 'Medium risk - may need review'),
        'signature': ('SIGNATURE', 'bold blue', 'Low risk - system permissions'),
        'unknown': ('UNKNOWN', 'bold white', 'Risk level not determined')
    }
    
    total_permissions = 0
    
    for status, count in status_count.items():
        total_permissions += count
        status_info = status_mapping.get(status, ('UNKNOWN', 'bold white', 'Unknown risk level'))
        
        perm_table.add_row(
            Text(status_info[0], style=status_info[1]),
            str(count),
            status_info[2]
        )
    
    if total_permissions > 0:
        # Show top dangerous permissions
        dangerous_perms = [p for p in permissions if p.get('status') == 'dangerous'][:5]
        
        if dangerous_perms:
            dangerous_table = Table(box=box.SIMPLE, title="Top Dangerous Permissions")
            dangerous_table.add_column("Permission", style="bold red")
            dangerous_table.add_column("Description", style="dim")
            
            for perm in dangerous_perms:
                dangerous_table.add_row(
                    perm.get('name', 'N/A'),
                    perm.get('description', '')[:100] + '...' if len(perm.get('description', '')) > 100 else perm.get('description', '')
                )
            
            console.print(Panel(dangerous_table, title="⚠️ Dangerous Permissions", title_align="left"))

def format_code_issues(console: Console, scan_data: Dict[str, Any]) -> None:
    """
    Format code analysis issues
    
    Args:
        console: Rich Console instance
        scan_data: Scan results data
    """
    code_analysis = scan_data.get('code_analysis', {})
    code_issues = code_analysis.get('code_issues', {})
    
    if not code_issues:
        return
    
    # Group issues by severity
    high_issues = []
    warning_issues = []
    
    for file_path, issues in code_issues.items():
        for issue in issues:
            severity = issue.get('severity', 'info')
            if severity == 'high':
                high_issues.append((file_path, issue))
            elif severity == 'warning':
                warning_issues.append((file_path, issue))
    
    # Display high severity issues
    if high_issues:
        high_table = Table(box=box.SIMPLE, title="High Severity Code Issues")
        high_table.add_column("File", style="cyan")
        high_table.add_column("Issue", style="bold red")
        high_table.add_column("Description", style="white")
        
        for file_path, issue in high_issues[:10]:  # Show top 10
            high_table.add_row(
                Path(file_path).name,
                issue.get('title', 'N/A'),
                issue.get('description', '')[:80] + '...' if len(issue.get('description', '')) > 80 else issue.get('description', '')
            )
        
        console.print(Panel(high_table, title="🚨 Critical Code Issues", title_align="left"))

def format_network_analysis(console: Console, scan_data: Dict[str, Any]) -> None:
    """
    Format network analysis results
    
    Args:
        console: Rich Console instance
        scan_data: Scan results data
    """
    network_analysis = scan_data.get('network_analysis', {})
    
    if not network_analysis:
        return
    
    network_table = Table(box=box.SIMPLE, title="Network Analysis")
    network_table.add_column("Domain", style="cyan")
    network_table.add_column("Status", style="bold")
    network_table.add_column("Details", style="white")
    
    domains = network_analysis.get('domains', [])
    for domain in domains[:10]:  # Show top 10
        network_table.add_row(
            domain.get('domain', 'N/A'),
            format_severity(domain.get('status', 'info')),
            domain.get('description', '')
        )
    
    if domains:
        console.print(Panel(network_table, title="🌐 Network Analysis", title_align="left"))

def format_dynamic_analysis_results(console: Console, dynamic_data: Dict[str, Any]) -> None:
    """
    Format dynamic analysis results
    
    Args:
        console: Rich Console instance
        dynamic_data: Dynamic analysis data
    """
    if not dynamic_data:
        return
    
    dyn_table = Table(box=box.ROUNDED, title="Dynamic Analysis Results")
    dyn_table.add_column("Test", style="cyan")
    dyn_table.add_column("Status", style="bold")
    dyn_table.add_column("Details", style="white")
    
    tests = dynamic_data.get('tests', {})
    for test_name, test_result in tests.items():
        status = test_result.get('status', 'unknown')
        dyn_table.add_row(
            test_name.replace('_', ' ').title(),
            format_severity(status),
            test_result.get('description', '')
        )
    
    console.print(Panel(dyn_table, title="🔬 Dynamic Analysis", title_align="left"))

def format_validation_results(console: Console, validation_results: Dict[str, Any]) -> None:
    """
    Format file validation results
    
    Args:
        console: Rich Console instance
        validation_results: Validation results from validators.comprehensive_file_validation
    """
    validation_table = Table(box=box.ROUNDED, title="File Validation Results")
    validation_table.add_column("Check", style="cyan", width=20)
    validation_table.add_column("Status", style="bold", width=12)
    validation_table.add_column("Details", style="white")
    
    # File existence
    if validation_results['is_valid']:
        validation_table.add_row("File Access", "✅ PASS", "File is accessible and readable")
    else:
        validation_table.add_row("File Access", "❌ FAIL", validation_results['errors'][0] if validation_results['errors'] else "Unknown error")
    
    # File type
    detected_type = validation_results.get('detected_type')
    if detected_type:
        validation_table.add_row("File Type", "✅ VALID", f"Detected as {detected_type}")
    else:
        validation_table.add_row("File Type", "❌ INVALID", "Unsupported file type")
    
    # File size
    file_size = validation_results.get('file_size', 0)
    size_mb = file_size / (1024 * 1024)
    validation_table.add_row("File Size", "✅ OK" if file_size > 0 else "❌ INVALID", f"{size_mb:.2f} MB")
    
    # Hash calculation
    file_hash = validation_results.get('file_hash')
    if file_hash:
        validation_table.add_row("Hash Calculation", "✅ SUCCESS", f"MD5: {file_hash}")
    else:
        validation_table.add_row("Hash Calculation", "⚠️ WARNING", "Could not calculate file hash")
    
    console.print(Panel(validation_table, title="📋 Validation Report", title_align="left"))
    
    # Show warnings if any
    warnings = validation_results.get('warnings', [])
    if warnings:
        warning_text = "\n".join([f"• {warning}" for warning in warnings])
        console.print(Panel(warning_text, title="⚠️ Warnings", title_align="left", style="yellow"))

# Helper function for Path
class Path:
    """Simple path helper"""
    @staticmethod
    def name(file_path: str) -> str:
        return file_path.split('/')[-1] if '/' in file_path else file_path.split('\\')[-1]