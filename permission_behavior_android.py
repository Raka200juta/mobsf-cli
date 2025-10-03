"""
Android Permission & Behavior Analysis - Enhanced Version
Custom modifications for comprehensive security assessment
"""

import re
import json
from collections import OrderedDict, defaultdict

# =============================================================================
# PERMISSION RISK ANALYSIS
# =============================================================================

ANDROID_PERMISSION_RISK_LEVELS = {
    'CRITICAL': {
        'risk_score': 100,
        'permissions': [
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS', 
            'android.permission.SEND_SMS',
            'android.permission.WRITE_SMS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.BIND_ACCESSIBILITY_SERVICE'
        ],
        'description': 'Dapat mencuri OTP, melacak lokasi, spyware, atau overlay attack'
    },
    'HIGH': {
        'risk_score': 80,
        'permissions': [
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.GET_ACCOUNTS'
        ],
        'description': 'Akses data pribadi, kontak, penyimpanan, dan telepon'
    },
    'MEDIUM': {
        'risk_score': 50,
        'permissions': [
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_ADMIN',
            'android.permission.BODY_SENSORS',
            'android.permission.NFC',
            'android.permission.USE_FINGERPRINT',
            'android.permission.USE_BIOMETRIC'
        ],
        'description': 'Akses sensor, Bluetooth, dan biometric data'
    },
    'LOW': {
        'risk_score': 20,
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.RECEIVE_BOOT_COMPLETED'
        ],
        'description': 'Izin normal untuk operasi dasar aplikasi'
    }
}

def analyze_permissions_enhanced(permissions_list):
    """
    Enhanced permission analysis dengan risk categorization
    """
    risk_categories = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': []
    }
    
    total_risk_score = 0
    
    for perm in permissions_list:
        perm_name = perm.strip()
        found = False
        
        for risk_level, data in ANDROID_PERMISSION_RISK_LEVELS.items():
            for risk_perm in data['permissions']:
                if risk_perm in perm_name:
                    risk_categories[risk_level].append({
                        'permission': perm_name,
                        'description': data['description'],
                        'risk_score': data['risk_score']
                    })
                    total_risk_score += data['risk_score']
                    found = True
                    break
            if found:
                break
        
        if not found:
            risk_categories['LOW'].append({
                'permission': perm_name,
                'description': 'Izin tidak dikenali',
                'risk_score': 10
            })
            total_risk_score += 10
    
    # Calculate overall risk level
    avg_risk_score = total_risk_score / max(len(permissions_list), 1)
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
        'total_permissions': len(permissions_list),
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

def check_financial_app_risk(permissions_list, app_name=""):
    """
    Cek risiko khusus untuk aplikasi financial (banking, e-wallet, payment)
    """
    financial_red_flags = {
        'CRITICAL_FINANCIAL_RISKS': [
            'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'WRITE_SMS',  # OTP Theft
            'SYSTEM_ALERT_WINDOW',  # Overlay attack
            'BIND_ACCESSIBILITY_SERVICE'  # Accessibility abuse
        ],
        'SUSPICIOUS_FOR_FINANCIAL': [
            'READ_CONTACTS', 'WRITE_CONTACTS',  # Contact stealing
            'RECORD_AUDIO', 'CAMERA',  # Spyware
            'ACCESS_FINE_LOCATION'  # Tracking
        ]
    }
    
    detected_risks = []
    critical_count = 0
    
    for perm in permissions_list:
        for risk_type, risk_list in financial_red_flags.items():
            for risk_perm in risk_list:
                if risk_perm in perm:
                    risk_level = 'CRITICAL' if risk_type == 'CRITICAL_FINANCIAL_RISKS' else 'HIGH'
                    detected_risks.append({
                        'permission': perm,
                        'risk_type': risk_type,
                        'risk_level': risk_level,
                        'description': f'Risiko {risk_perm} untuk aplikasi financial'
                    })
                    if risk_level == 'CRITICAL':
                        critical_count += 1
                    break
    
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
        'recommendation': generate_financial_recommendation(financial_risk_level, critical_count)
    }

def generate_financial_recommendation(risk_level, critical_count):
    """Generate rekomendasi berdasarkan level risiko financial"""
    recommendations = {
        'CRITICAL': '🚨 APLIKASI BERBAHAYA: Memiliki multiple critical risks untuk aplikasi financial!',
        'HIGH': '⚠️ APLIKASI MENcurigakan: Memiliki permission berisiko tinggi untuk aplikasi financial',
        'MEDIUM': '🔶 APLIKASI PERLU DICURIGAI: Beberapa permission tidak biasa untuk aplikasi financial',
        'LOW': '✅ APLIKASI AMAN: Permission sesuai untuk aplikasi financial'
    }
    return recommendations.get(risk_level, '⚠️ Risk level tidak dikenali')

# =============================================================================
# BEHAVIOR & MALWARE ANALYSIS
# =============================================================================

ANDROID_BEHAVIOR_PATTERNS = {
    'BANKING_TROJAN': {
        'indicators': [
            'SmsManager', 'telephony.SmsManager',  # SMS operations
            'getDeviceId', 'getSubscriberId',  # Device ID access
            'onAccessibilityEvent',  # Accessibility abuse
            'TYPE_APPLICATION_OVERLAY',  # Overlay windows
            'addView.*WindowManager'  # Dynamic view adding
        ],
        'risk_level': 'CRITICAL',
        'description': 'Indikasi banking trojan - bisa mencuri OTP dan data banking'
    },
    'SPYWARE': {
        'indicators': [
            'MediaRecorder', 'AudioRecord',  # Audio recording
            'Camera.*open', 'takePicture',  # Camera access
            'LocationManager', 'getLastLocation',  # Location tracking
            'getRunningTasks', 'getRunningServices'  # Activity monitoring
        ],
        'risk_level': 'HIGH',
        'description': 'Indikasi spyware - memantau aktivitas pengguna'
    },
    'DATA_HARVESTER': {
        'indicators': [
            'getContacts', 'ContactsContract',  # Contact access
            'CallLog', 'CallLog.Calls',  # Call log access
            'query.*Contacts',  # Contact querying
            'Browser.*BOOKMARKS', 'Browser.*HISTORY'  # Browser data
        ],
        'risk_level': 'HIGH',
        'description': 'Indikasi data harvester - mencuri data pribadi'
    },
    'ADWARE': {
        'indicators': [
            'AdView', 'AdMob', 'AdManager',  # Ad libraries
            'loadAd', 'showAd', 'displayAd',  # Ad operations
            'interstitial', 'bannerad',  # Ad types
            'MoPub', 'UnityAds'  # Ad networks
        ],
        'risk_level': 'MEDIUM',
        'description': 'Indikasi adware - aggressive advertising'
    },
    'ROOT_DETECTION': {
        'indicators': [
            'su', 'Superuser',  # Root binaries
            '/system/bin/su', '/system/xbin/su',  # Root paths
            'RootTools', 'RootBeer',  # Root detection libraries
            'isDeviceRooted', 'checkRoot'  # Root check methods
        ],
        'risk_level': 'MEDIUM',
        'description': 'Aplikasi melakukan root detection'
    }
}

def analyze_behavior_patterns(decompiled_code, app_metadata):
    """
    Analisis perilaku mencurigakan dari decompiled code
    """
    behavior_findings = {
        'detected_threats': [],
        'suspicious_activities': [],
        'privacy_concerns': [],
        'overall_behavior_risk': 'LOW'
    }
    
    threat_count = defaultdict(int)
    
    # Scan untuk setiap pattern
    for threat_type, pattern_data in ANDROID_BEHAVIOR_PATTERNS.items():
        for indicator in pattern_data['indicators']:
            if re.search(indicator, decompiled_code, re.IGNORECASE):
                threat_count[threat_type] += 1
                behavior_findings['detected_threats'].append({
                    'threat_type': threat_type,
                    'indicator_found': indicator,
                    'risk_level': pattern_data['risk_level'],
                    'description': pattern_data['description'],
                    'confidence': 'HIGH' if threat_count[threat_type] > 2 else 'MEDIUM'
                })
                break  # Cukup 1 indicator per threat type
    
    # Analyze permission-behavior correlation
    permission_behavior_correlation(behavior_findings, app_metadata)
    
    # Calculate overall behavior risk
    behavior_findings['overall_behavior_risk'] = calculate_behavior_risk(behavior_findings)
    
    return behavior_findings

def permission_behavior_correlation(behavior_findings, app_metadata):
    """
    Korelasi antara permission dan behavior patterns
    """
    suspicious_correlations = []
    
    # Check jika ada SMS permission tapi bukan messaging app
    if app_metadata.get('has_sms_permission') and not app_metadata.get('is_messaging_app'):
        suspicious_correlations.append({
            'type': 'SMS_ACCESS_MISMATCH',
            'description': 'Aplikasi memiliki SMS permission tapi bukan messaging app',
            'risk_level': 'HIGH'
        })
    
    # Check jika ada camera permission tanpa camera-related features
    if app_metadata.get('has_camera_permission') and not app_metadata.get('has_camera_features'):
        suspicious_correlations.append({
            'type': 'CAMERA_ACCESS_SUSPICIOUS', 
            'description': 'Aplikasi memiliki camera permission tanpa fitur camera yang jelas',
            'risk_level': 'MEDIUM'
        })
    
    behavior_findings['suspicious_correlations'] = suspicious_correlations

def calculate_behavior_risk(behavior_findings):
    """
    Hitung overall behavior risk score
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
    
    for correlation in behavior_findings.get('suspicious_correlations', []):
        total_score += risk_weights.get(correlation['risk_level'], 1)
    
    max_possible_score = (len(behavior_findings['detected_threats']) + 
                         len(behavior_findings.get('suspicious_correlations', []))) * 4
    
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
# MAIN COMPREHENSIVE ANALYSIS FUNCTION
# =============================================================================

def comprehensive_android_analysis(permissions_list, decompiled_code="", app_metadata=None):
    """
    Comprehensive analysis combining permissions and behavior
    """
    if app_metadata is None:
        app_metadata = {}
    
    # 1. Permission Analysis
    permission_analysis = analyze_permissions_enhanced(permissions_list)
    
    # 2. Financial App Risk Check
    financial_risk = check_financial_app_risk(permissions_list, app_metadata.get('app_name', ''))
    
    # 3. Behavior Analysis (if decompiled code available)
    behavior_analysis = {}
    if decompiled_code:
        behavior_analysis = analyze_behavior_patterns(decompiled_code, app_metadata)
    
    # 4. Overall Security Assessment
    overall_security = generate_security_assessment(permission_analysis, financial_risk, behavior_analysis)
    
    return {
        'permission_analysis': permission_analysis,
        'financial_risk_assessment': financial_risk,
        'behavior_analysis': behavior_analysis,
        'overall_security_assessment': overall_security,
        'generated_at': '2024-01-01 00:00:00',  # Timestamp placeholder
        'analysis_version': '1.0'
    }

def generate_security_assessment(permission_analysis, financial_risk, behavior_analysis):
    """
    Generate overall security assessment berdasarkan semua analisis
    """
    # Calculate composite risk score
    permission_risk_weight = 0.4
    financial_risk_weight = 0.3
    behavior_risk_weight = 0.3
    
    risk_scores = {
        'CRITICAL': 100,
        'HIGH': 75, 
        'MEDIUM': 50,
        'LOW': 25
    }
    
    permission_score = risk_scores.get(permission_analysis['overall_risk_level'], 25)
    financial_score = risk_scores.get(financial_risk['financial_risk_level'], 25)
    behavior_score = risk_scores.get(behavior_analysis.get('overall_behavior_risk', 'LOW'), 25)
    
    composite_score = (
        permission_score * permission_risk_weight +
        financial_score * financial_risk_weight + 
        behavior_score * behavior_risk_weight
    )
    
    # Determine overall risk level
    if composite_score >= 80:
        overall_risk = 'CRITICAL'
        recommendation = '🚨 APLIKASI BERBAHAYA: Tidak disarankan untuk diinstall!'
    elif composite_score >= 60:
        overall_risk = 'HIGH'
        recommendation = '⚠️ APLIKASI BERISIKO TINGGI: Perlu pemeriksaan manual lebih lanjut'
    elif composite_score >= 40:
        overall_risk = 'MEDIUM'
        recommendation = '🔶 APLIKASI BERISIKO SEDANG: Beberapa permission/behavior mencurigakan'
    else:
        overall_risk = 'LOW'
        recommendation = '✅ APLIKASI AMAN: Tidak ditemukan indikasi berbahaya'
    
    return {
        'composite_risk_score': round(composite_score, 2),
        'overall_risk_level': overall_risk,
        'recommendation': recommendation,
        'risk_breakdown': {
            'permission_risk': permission_analysis['overall_risk_level'],
            'financial_risk': financial_risk['financial_risk_level'],
            'behavior_risk': behavior_analysis.get('overall_behavior_risk', 'LOW')
        }
    }

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_security_report(analysis_results, output_format='text'):
    """
    Generate human-readable security report
    """
    report = []
    
    # Header
    report.append("=" * 60)
    report.append("ANDROID SECURITY ANALYSIS REPORT")
    report.append("=" * 60)
    
    # Permission Analysis
    perm_analysis = analysis_results['permission_analysis']
    report.append("\n📋 PERMISSION ANALYSIS:")
    report.append(f"   Total Permissions: {perm_analysis['total_permissions']}")
    report.append(f"   Risk Breakdown: CRITICAL({perm_analysis['risk_breakdown']['CRITICAL']}) "
                  f"HIGH({perm_analysis['risk_breakdown']['HIGH']}) "
                  f"MEDIUM({perm_analysis['risk_breakdown']['MEDIUM']}) "
                  f"LOW({perm_analysis['risk_breakdown']['LOW']})")
    report.append(f"   Overall Risk: {perm_analysis['overall_risk_level']}")
    
    # Financial Risk
    financial = analysis_results['financial_risk_assessment']
    report.append(f"\n🏦 FINANCIAL APP RISK: {financial['financial_risk_level']}")
    report.append(f"   Detected Risks: {financial['total_risks_count']} "
                  f"(Critical: {financial['critical_risks_count']})")
    report.append(f"   Recommendation: {financial['recommendation']}")
    
    # Behavior Analysis
    if analysis_results['behavior_analysis']:
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
        return analysis_results  # Return raw JSON for other formats