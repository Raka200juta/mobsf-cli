"""
iOS Permission & Behavior Analysis - Enhanced Version
Custom modifications for comprehensive iOS security assessment
"""

import re
import json
import plistlib
from collections import OrderedDict, defaultdict

# =============================================================================
# iOS PERMISSION RISK ANALYSIS
# =============================================================================

IOS_PERMISSION_RISK_LEVELS = {
    'CRITICAL': {
        'risk_score': 100,
        'permissions': [
            'NSCameraUsageDescription',
            'NSMicrophoneUsageDescription', 
            'NSLocationAlwaysUsageDescription',
            'NSLocationWhenInUseUsageDescription',
            'NSFaceIDUsageDescription'
        ],
        'description': 'Akses kamera, mikrofon, lokasi terus-menerus, atau FaceID - risiko privasi tinggi'
    },
    'HIGH': {
        'risk_score': 80,
        'permissions': [
            'NSContactsUsageDescription',
            'NSPhotoLibraryUsageDescription',
            'NSBluetoothAlwaysUsageDescription',
            'NSBluetoothPeripheralUsageDescription',
            'NSCalendarsUsageDescription',
            'NSRemindersUsageDescription'
        ],
        'description': 'Akses kontak, foto, Bluetooth, kalender - data pribadi sensitif'
    },
    'MEDIUM': {
        'risk_score': 50,
        'permissions': [
            'NSMotionUsageDescription',
            'NSSiriUsageDescription',
            'NSHealthShareUsageDescription',
            'NSHealthUpdateUsageDescription',
            'NSHomeKitUsageDescription'
        ],
        'description': 'Akses motion data, Siri, health data, homekit'
    },
    'LOW': {
        'risk_score': 20,
        'permissions': [
            'NSAppleMusicUsageDescription',
            'NSSpeechRecognitionUsageDescription',
            'NSLocalNetworkUsageDescription',
            'NSFallbackUsageDescription'
        ],
        'description': 'Akses terbatas untuk fungsi normal aplikasi'
    }
}

IOS_CAPABILITY_RISKS = {
    'CRITICAL': {
        'risk_score': 100,
        'capabilities': [
            'com.apple.developer.associated-domains',
            'com.apple.developer.default-data-protection',
            'com.apple.developer.healthkit',
            'com.apple.developer.homekit',
            'com.apple.developer.networking.vpn.api',
            'com.apple.security.application-groups'
        ],
        'description': 'Capabilities dengan akses data sensitif atau system-level'
    },
    'HIGH': {
        'risk_score': 80,
        'capabilities': [
            'com.apple.developer.in-app-payments',
            'com.apple.developer.networking.HotspotConfiguration',
            'com.apple.developer.nfc.readersession.formats',
            'inter-app-audio',
            'com.apple.developer.usernotifications.communication'
        ],
        'description': 'Capabilities dengan akses payment, network, atau komunikasi'
    },
    'MEDIUM': {
        'risk_score': 50,
        'capabilities': [
            'com.apple.developer.game-center',
            'com.apple.developer.arkit',
            'com.apple.external-accessory.wireless-configuration'
        ],
        'description': 'Capabilities untuk gaming, AR, atau accessories'
    }
}

def analyze_ios_permissions_enhanced(plist_data):
    """
    Enhanced iOS permission analysis dari Info.plist
    """
    risk_categories = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': []
    }
    
    total_risk_score = 0
    usage_descriptions_found = 0
    
    # Analisis Usage Descriptions dari Info.plist
    for key, value in plist_data.items():
        if 'UsageDescription' in key:
            usage_descriptions_found += 1
            found = False
            
            for risk_level, data in IOS_PERMISSION_RISK_LEVELS.items():
                if key in data['permissions']:
                    risk_categories[risk_level].append({
                        'permission': key,
                        'user_description': str(value),
                        'risk_description': data['description'],
                        'risk_score': data['risk_score']
                    })
                    total_risk_score += data['risk_score']
                    found = True
                    break
            
            if not found:
                risk_categories['LOW'].append({
                    'permission': key,
                    'user_description': str(value),
                    'risk_description': 'Izin iOS tidak dikenali',
                    'risk_score': 10
                })
                total_risk_score += 10
    
    # Calculate overall risk
    avg_risk_score = total_risk_score / max(usage_descriptions_found, 1)
    if avg_risk_score >= 70:
        overall_risk = 'CRITICAL'
    elif avg_risk_score >= 50:
        overall_risk = 'HIGH'
    elif avg_risk_score >= 30:
        overall_risk = 'MEDIUM'
    else:
        overall_risk = 'LOW'
    
    return {
        'risk_categories': risk_categories,
        'total_usage_descriptions': usage_descriptions_found,
        'total_risk_score': total_risk_score,
        'average_risk_score': round(avg_risk_score, 2),
        'overall_risk_level': overall_risk,
        'risk_breakdown': {
            'CRITICAL': len(risk_categories['CRITICAL']),
            'HIGH': len(risk_categories['HIGH']),
            'MEDIUM': len(risk_categories['MEDIUM']),
            'LOW': len(risk_categories['LOW'])
        }
    }

def analyze_ios_capabilities_enhanced(entitlements_data):
    """
    Analisis capabilities dari entitlements file
    """
    capability_risks = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': []
    }
    
    total_capability_score = 0
    
    if not entitlements_data:
        return {
            'capability_risks': capability_risks,
            'total_capabilities': 0,
            'overall_capability_risk': 'LOW'
        }
    
    for cap_key, cap_value in entitlements_data.items():
        found = False
        
        for risk_level, data in IOS_CAPABILITY_RISKS.items():
            if cap_key in data['capabilities']:
                capability_risks[risk_level].append({
                    'capability': cap_key,
                    'value': cap_value,
                    'description': data['description'],
                    'risk_score': data['risk_score']
                })
                total_capability_score += data['risk_score']
                found = True
                break
        
        if not found:
            capability_risks['LOW'].append({
                'capability': cap_key,
                'value': cap_value,
                'description': 'Capability normal',
                'risk_score': 10
            })
            total_capability_score += 10
    
    # Calculate capability risk
    avg_cap_score = total_capability_score / max(len(entitlements_data), 1)
    if avg_cap_score >= 70:
        cap_risk = 'CRITICAL'
    elif avg_cap_score >= 50:
        cap_risk = 'HIGH'
    elif avg_cap_score >= 30:
        cap_risk = 'MEDIUM'
    else:
        cap_risk = 'LOW'
    
    return {
        'capability_risks': capability_risks,
        'total_capabilities': len(entitlements_data),
        'total_capability_score': total_capability_score,
        'average_capability_score': round(avg_cap_score, 2),
        'overall_capability_risk': cap_risk
    }

def check_ios_financial_app_risk(plist_data, entitlements_data, app_metadata=None):
    """
    Cek risiko khusus untuk aplikasi financial iOS (banking, e-wallet, payment)
    """
    if app_metadata is None:
        app_metadata = {}
    
    financial_red_flags = {
        'CRITICAL_FINANCIAL_RISKS': [
            'NSFaceIDUsageDescription',  # Biometric data for financial apps
            'NSCameraUsageDescription',  # Document scanning
            'NSLocationAlwaysUsageDescription'  # Continuous tracking
        ],
        'SUSPICIOUS_CAPABILITIES': [
            'com.apple.developer.associated-domains',  # Universal links
            'com.apple.developer.in-app-payments',  # Payment processing
            'com.apple.security.application-groups'  # Data sharing between apps
        ]
    }
    
    detected_risks = []
    critical_count = 0
    
    # Check permissions
    for key in plist_data:
        if key in financial_red_flags['CRITICAL_FINANCIAL_RISKS']:
            critical_count += 1
            detected_risks.append({
                'type': 'PERMISSION',
                'item': key,
                'risk_level': 'CRITICAL',
                'description': f'{key} - critical permission untuk aplikasi financial',
                'user_description': plist_data.get(key, 'No description')
            })
    
    # Check capabilities
    if entitlements_data:
        for cap in financial_red_flags['SUSPICIOUS_CAPABILITIES']:
            if cap in entitlements_data:
                detected_risks.append({
                    'type': 'CAPABILITY',
                    'item': cap,
                    'risk_level': 'HIGH',
                    'description': f'{cap} - capability sensitive untuk financial apps',
                    'value': entitlements_data[cap]
                })
    
    # Determine financial risk level
    if critical_count >= 2:
        financial_risk_level = 'CRITICAL'
    elif critical_count >= 1 or len(detected_risks) >= 3:
        financial_risk_level = 'HIGH'
    elif detected_risks:
        financial_risk_level = 'MEDIUM'
    else:
        financial_risk_level = 'LOW'
    
    return {
        'is_financial_app_risk': len(detected_risks) > 0,
        'detected_risks': detected_risks,
        'financial_risk_level': financial_risk_level,
        'critical_risks_count': critical_count,
        'total_risks_count': len(detected_risks),
        'recommendation': generate_ios_financial_recommendation(financial_risk_level, critical_count)
    }

def generate_ios_financial_recommendation(risk_level, critical_count):
    """Generate rekomendasi untuk iOS financial apps"""
    recommendations = {
        'CRITICAL': '🚨 APLIKASI iOS BERBAHAYA: Multiple critical risks terdeteksi!',
        'HIGH': '⚠️ APLIKASI iOS MENcurigakan: Permission/capability berisiko tinggi terdeteksi',
        'MEDIUM': '🔶 APLIKASI iOS PERLU DICURIGAI: Beberapa permission tidak biasa',
        'LOW': '✅ APLIKASI iOS AMAN: Permission sesuai untuk aplikasi financial'
    }
    return recommendations.get(risk_level, '⚠️ Risk level tidak dikenali')

# =============================================================================
# iOS BEHAVIOR & MALWARE ANALYSIS - DIPERBAIKI
# =============================================================================

IOS_BEHAVIOR_PATTERNS = {
    'JAILBREAK_DETECTION': {
        'indicators': [
            '/Applications/Cydia.app',
            '/Library/MobileSubstrate/MobileSubstrate.dylib',
            '/bin/bash', '/usr/sbin/sshd',
            '/etc/apt', '/private/var/lib/apt/',
            'cydia://', 'sileo://'
        ],
        'risk_level': 'MEDIUM',
        'description': 'Aplikasi melakukan jailbreak detection'
    },
    'PRIVACY_VIOLATIONS': {
        'indicators': [
            'UIPasteboardNameGeneral',  # Clipboard access
            'identifierForVendor', 'advertisingIdentifier',  # Device ID
            'UDID', 'uniqueIdentifier',  # Banned identifiers
            'MFMessageComposeViewController'  # Message composing
        ],
        'risk_level': 'HIGH',
        'description': 'Indikasi privacy violations atau data collection'
    },
    'SUSPICIOUS_FRAMEWORKS': {
        'indicators': [
            'CydiaSubstrate', 'MobileSubstrate', 'libhooker',
            'FridaGadget', 'cycript', 'zdynamiclibraries'
        ],
        'risk_level': 'CRITICAL',
        'description': 'Framework mencurigakan - mungkin modified binary'
    },
    'BACKGROUND_ACTIVITIES': {  # ✅ DIPERBAIKI: sekarang string yang valid
        'indicators': [
            'backgroundModes', 'UIBackgroundMode',
            'audio', 'location', 'voip', 'bluetooth-central'
        ],
        'risk_level': 'MEDIUM',
        'description': 'Background activities yang extensive'
    },
    'SUSPICIOUS_URL_HANDLING': {
        'indicators': [
            'openURL', 'application:openURL',
            'handleOpenURL', 'canOpenURL'
        ],
        'risk_level': 'MEDIUM',
        'description': 'URL handling yang bisa digunakan untuk phishing'
    }
}

def analyze_ios_behavior_patterns(binary_analysis, plist_data, entitlements_data):
    """
    Analisis perilaku mencurigakan di iOS app
    """
    behavior_findings = {
        'detected_threats': [],
        'suspicious_activities': [],
        'privacy_concerns': [],
        'overall_behavior_risk': 'LOW'
    }
    
    # Combine all text for pattern matching
    analysis_text = ""
    
    # Add plist content
    for key, value in plist_data.items():
        analysis_text += f"{key}: {value}\n"
    
    # Add entitlements content  
    if entitlements_data:
        for key, value in entitlements_data.items():
            analysis_text += f"{key}: {value}\n"
    
    # Add binary analysis info if available
    if binary_analysis and 'strings' in binary_analysis:
        analysis_text += "\n".join(binary_analysis.get('strings', []))
    
    # Scan untuk setiap pattern
    threat_count = defaultdict(int)
    
    for threat_type, pattern_data in IOS_BEHAVIOR_PATTERNS.items():
        for indicator in pattern_data['indicators']:
            if re.search(re.escape(indicator), analysis_text, re.IGNORECASE):
                threat_count[threat_type] += 1
                behavior_findings['detected_threats'].append({
                    'threat_type': threat_type,
                    'indicator_found': indicator,
                    'risk_level': pattern_data['risk_level'],
                    'description': pattern_data['description'],
                    'confidence': 'HIGH' if threat_count[threat_type] > 1 else 'MEDIUM'
                })
                break
    
    # Check for suspicious URL schemes
    suspicious_schemes = analyze_url_schemes(plist_data)
    if suspicious_schemes:
        behavior_findings['suspicious_activities'].extend(suspicious_schemes)
    
    # Calculate overall behavior risk
    behavior_findings['overall_behavior_risk'] = calculate_ios_behavior_risk(behavior_findings)
    
    return behavior_findings

def analyze_url_schemes(plist_data):
    """
    Analisis URL schemes untuk potential phishing atau malicious redirects
    """
    suspicious_schemes = []
    
    # Check CFBundleURLTypes
    if 'CFBundleURLTypes' in plist_data:
        for url_type in plist_data['CFBundleURLTypes']:
            if 'CFBundleURLSchemes' in url_type:
                for scheme in url_type['CFBundleURLSchemes']:
                    scheme_lower = scheme.lower()
                    # Check for suspicious scheme names
                    if any(suspicious in scheme_lower for suspicious in ['auth', 'login', 'oauth', 'bank', 'payment']):
                        suspicious_schemes.append({
                            'type': 'SUSPICIOUS_URL_SCHEME',
                            'scheme': scheme,
                            'risk_level': 'MEDIUM',
                            'description': f'URL scheme mencurigakan: {scheme}'
                        })
    
    return suspicious_schemes

def calculate_ios_behavior_risk(behavior_findings):
    """
    Hitung overall behavior risk score untuk iOS
    """
    risk_weights = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2, 
        'LOW': 1
    }
    
    total_score = 0
    max_possible_score = 0
    
    for threat in behavior_findings['detected_threats']:
        total_score += risk_weights.get(threat['risk_level'], 1)
    
    for activity in behavior_findings.get('suspicious_activities', []):
        total_score += risk_weights.get(activity['risk_level'], 1)
    
    max_possible_score = (len(behavior_findings['detected_threats']) + 
                         len(behavior_findings.get('suspicious_activities', []))) * 4
    
    if max_possible_score == 0:
        return 'LOW'
    
    risk_ratio = total_score / max_possible_score
    
    if risk_ratio >= 0.7:
        return 'CRITICAL'
    elif risk_ratio >= 0.5:
        return 'HIGH'
    elif risk_ratio >= 0.3:
        return 'MEDIUM'
    else:
        return 'LOW'

# =============================================================================
# MAIN COMPREHENSIVE iOS ANALYSIS FUNCTION
# =============================================================================

def comprehensive_ios_analysis(plist_data, entitlements_data=None, binary_analysis=None, app_metadata=None):
    """
    Comprehensive analysis untuk iOS app
    """
    if app_metadata is None:
        app_metadata = {}
    if entitlements_data is None:
        entitlements_data = {}
    
    # 1. Permission Analysis dari Info.plist
    permission_analysis = analyze_ios_permissions_enhanced(plist_data)
    
    # 2. Capability Analysis dari entitlements
    capability_analysis = analyze_ios_capabilities_enhanced(entitlements_data)
    
    # 3. Financial App Risk Check
    financial_risk = check_ios_financial_app_risk(plist_data, entitlements_data, app_metadata)
    
    # 4. Behavior Analysis
    behavior_analysis = analyze_ios_behavior_patterns(binary_analysis, plist_data, entitlements_data)
    
    # 5. Overall Security Assessment
    overall_security = generate_ios_security_assessment(
        permission_analysis, 
        capability_analysis, 
        financial_risk, 
        behavior_analysis
    )
    
    return {
        'permission_analysis': permission_analysis,
        'capability_analysis': capability_analysis,
        'financial_risk_assessment': financial_risk,
        'behavior_analysis': behavior_analysis,
        'overall_security_assessment': overall_security,
        'generated_at': '2024-01-01 00:00:00',
        'analysis_version': '1.0'
    }

def generate_ios_security_assessment(permission_analysis, capability_analysis, financial_risk, behavior_analysis):
    """
    Generate overall security assessment untuk iOS
    """
    # Calculate composite risk score
    permission_risk_weight = 0.3
    capability_risk_weight = 0.3
    financial_risk_weight = 0.2
    behavior_risk_weight = 0.2
    
    risk_scores = {
        'CRITICAL': 100,
        'HIGH': 75,
        'MEDIUM': 50,
        'LOW': 25
    }
    
    permission_score = risk_scores.get(permission_analysis['overall_risk_level'], 25)
    capability_score = risk_scores.get(capability_analysis['overall_capability_risk'], 25)
    financial_score = risk_scores.get(financial_risk['financial_risk_level'], 25)
    behavior_score = risk_scores.get(behavior_analysis['overall_behavior_risk'], 25)
    
    composite_score = (
        permission_score * permission_risk_weight +
        capability_score * capability_risk_weight +
        financial_score * financial_risk_weight +
        behavior_score * behavior_risk_weight
    )
    
    # Determine overall risk level
    if composite_score >= 80:
        overall_risk = 'CRITICAL'
        recommendation = '🚨 APLIKASI iOS BERBAHAYA: Tidak disarankan untuk diinstall!'
    elif composite_score >= 60:
        overall_risk = 'HIGH'
        recommendation = '⚠️ APLIKASI iOS BERISIKO TINGGI: Perlu pemeriksaan manual'
    elif composite_score >= 40:
        overall_risk = 'MEDIUM'
        recommendation = '🔶 APLIKASI iOS BERISIKO SEDANG: Beberapa indikasi mencurigakan'
    else:
        overall_risk = 'LOW'
        recommendation = '✅ APLIKASI iOS AMAN: Tidak ditemukan indikasi berbahaya'
    
    return {
        'composite_risk_score': round(composite_score, 2),
        'overall_risk_level': overall_risk,
        'recommendation': recommendation,
        'risk_breakdown': {
            'permission_risk': permission_analysis['overall_risk_level'],
            'capability_risk': capability_analysis['overall_capability_risk'],
            'financial_risk': financial_risk['financial_risk_level'],
            'behavior_risk': behavior_analysis['overall_behavior_risk']
        }
    }

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_ios_security_report(analysis_results, output_format='text'):
    """
    Generate human-readable security report untuk iOS
    """
    report = []
    
    # Header
    report.append("=" * 60)
    report.append("iOS SECURITY ANALYSIS REPORT")
    report.append("=" * 60)
    
    # Permission Analysis
    perm_analysis = analysis_results['permission_analysis']
    report.append("\n📋 PERMISSION ANALYSIS:")
    report.append(f"   Total Usage Descriptions: {perm_analysis['total_usage_descriptions']}")
    report.append(f"   Risk Breakdown: CRITICAL({perm_analysis['risk_breakdown']['CRITICAL']}) "
                  f"HIGH({perm_analysis['risk_breakdown']['HIGH']}) "
                  f"MEDIUM({perm_analysis['risk_breakdown']['MEDIUM']}) "
                  f"LOW({perm_analysis['risk_breakdown']['LOW']})")
    report.append(f"   Overall Risk: {perm_analysis['overall_risk_level']}")
    
    # Capability Analysis
    cap_analysis = analysis_results['capability_analysis']
    report.append(f"\n🔧 CAPABILITY ANALYSIS:")
    report.append(f"   Total Capabilities: {cap_analysis['total_capabilities']}")
    report.append(f"   Risk Level: {cap_analysis['overall_capability_risk']}")
    
    # Financial Risk
    financial = analysis_results['financial_risk_assessment']
    report.append(f"\n🏦 FINANCIAL APP RISK: {financial['financial_risk_level']}")
    report.append(f"   Detected Risks: {financial['total_risks_count']} "
                  f"(Critical: {financial['critical_risks_count']})")
    report.append(f"   Recommendation: {financial['recommendation']}")
    
    # Behavior Analysis
    behavior = analysis_results['behavior_analysis']
    report.append(f"\n🔍 BEHAVIOR ANALYSIS: {behavior['overall_behavior_risk']}")
    report.append(f"   Detected Threats: {len(behavior['detected_threats'])}")
    
    # Overall Assessment
    overall = analysis_results['overall_security_assessment']
    report.append(f"\n🎯 OVERALL SECURITY ASSESSMENT:")
    report.append(f"   Composite Score: {overall['composite_risk_score']}/100")
    report.append(f"   Risk Level: {overall['overall_risk_level']}")
    report.append(f"   Recommendation: {overall['recommendation']}")
    
    report.append("\n" + "=" * 60)
    
    if output_format == 'text':
        return '\n'.join(report)
    else:
        return analysis_results

# =============================================================================
# PLIST PARSING UTILITIES
# =============================================================================

def parse_plist_file(plist_path):
    """
    Parse Info.plist file dan extract relevant data
    """
    try:
        with open(plist_path, 'rb') as f:
            plist_data = plistlib.load(f)
        
        # Extract usage descriptions
        usage_descriptions = {}
        for key, value in plist_data.items():
            if 'UsageDescription' in key:
                usage_descriptions[key] = value
        
        # Extract URL schemes
        url_schemes = []
        if 'CFBundleURLTypes' in plist_data:
            for url_type in plist_data['CFBundleURLTypes']:
                if 'CFBundleURLSchemes' in url_type:
                    url_schemes.extend(url_type['CFBundleURLSchemes'])
        
        return {
            'plist_data': plist_data,
            'usage_descriptions': usage_descriptions,
            'url_schemes': url_schemes,
            'bundle_id': plist_data.get('CFBundleIdentifier', ''),
            'app_name': plist_data.get('CFBundleName', ''),
            'version': plist_data.get('CFBundleShortVersionString', '')
        }
    except Exception as e:
        return {'error': f'Failed to parse plist: {str(e)}'}