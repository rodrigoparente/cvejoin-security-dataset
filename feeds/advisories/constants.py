
MICROSOFT_BASE_URL = 'https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/'
MICROSOFT_OUTPUT_FILE_PATH = 'output/microsoft_advisory.csv'
START_YEAR = 2016
END_YEAR = 2022

MICROSOFT_IMPACT_MAP = {
    'Remote Code Execution': 'remote code execution',
    'Elevation of Privilege': 'elevation of privilege',
    'Information Disclosure': 'information disclosure',
    'Security Feature Bypass': 'security feature bypass',
    'Denial of Service': 'denial of service',
    'Spoofing': 'spoofing',
    'Tampering': 'tampering',
    'Defense in Depth': 'defense in depth'
}

INTEL_BASE_URL = 'https://www.intel.com'
INTEL_SECURITY_BULLETIN = 'content/www/us/en/security-center/default.html'
INTEL_OUTPUT_FILE_PATH = 'output/intel_advisory.csv'

INTEL_IMPACT_MAP = {
    'Elevation of Privilege': 'elevation of privilege',
    'Escalation of Privilege': 'elevation of privilege',
    'Information Disclosure': 'information disclosure',
    'Denial of Service': 'denial of service'
}

ADOBE_BASE_URL = 'https://helpx.adobe.com'
ADOBE_SECURITY_BULLETIN = 'security/security-bulletin.html'
ADOBE_OUTPUT_FILE_PATH = 'output/adobe_advisory.csv'

ADOBE_IMPACT_MAP = {
    'Remote Code Execution': 'remote code execution',
    'Remote code execution': 'remote code execution',
    'Local Privilege Escalation': 'elevation of privilege',
    'Local privilege escalation': 'elevation of privilege',
    'PrivilegeEscalation': 'elevation of privilege',
    'Privilege Escalation': 'elevation of privilege',
    'Privilegeescalation': 'elevation of privilege',
    'Privilege escalation': 'elevation of privilege',
    'Escalation of privilege': 'elevation of privilege',
    'Sensitive information disclosure': 'information disclosure',
    'Sensitive Information disclosure': 'information disclosure',
    'Information Disclosure': 'information disclosure',
    'InformationDisclosure': 'information disclosure',
    'Information Leakage': 'information disclosure',
    'Sensitive Information Disclosure': 'information disclosure',
    'Information disclosure': 'information disclosure',
    'Sensitive data disclosure if SMB request is subject to a relay attack': 'information disclosure',  # noqa e501
    'System file structure disclosure': 'information disclosure',
    'Security bypass': 'security feature bypass',
    'Access Control Bypass': 'security feature bypass',
    'Security Mitigation Bypass': 'security feature bypass',
    'Security Bypass': 'security feature bypass',
    'Network access control bypass': 'security feature bypass',
    'Security feature bypass': 'security feature bypass',
    'Denial-of-service': 'denial of service',
    'Denial of Service': 'denial of service',
    'Application-level denial-of-service (DoS)': 'denial of service',
    'Application denial of service': 'denial of service',
    'Application Denial of Service': 'denial of service',
    'Application denial-of-service': 'denial of service',
    'Excessive resource consumption': 'denial of service',
    'Session hijacking': 'spoofing',
    'Exposure of the privileges granted to a session': 'spoofing',
    'Arbitrary folder creation': 'tampering',
    'ArbitraryFile Deletion': 'tampering',
    'Arbitrary file system write': 'tampering',
    'Arbitrary fileoverwrite': 'tampering',
    'Arbitrary file deletion': 'tampering',
    'Unauthorized Information Modification': 'tampering',
    'Minimal (defense-in-depth fix)': 'defense in depth',
    'Cross-site scripting attacks': 'xss',
    'DOM-based cross-site scripting attack': 'xss',
    'Clickjacking attacks': 'xss',
    'Arbitrary code execution of files located in the webroot or its subdirectory': 'arbitrary code execution',  # noqa e501
    'Arbitrary Code Execution': 'arbitrary code execution',
    'Arbitrarycode execution': 'arbitrary code execution',
    'Arbitrary code executio': 'arbitrary code execution',
    'ArbitraryCode Execution': 'arbitrary code execution',
    'Arbitrary code execution': 'arbitrary code execution',
    'Local Code Execution': 'arbitrary code execution',
    'Memory Leak': 'memory leak',
    'Memory leak': 'memory leak',
    'Memory address disclosure': 'memory leak',
    'Dynamic library injection': 'none',
    'Arbitrary JavaScript Execution': 'none',
    'Arbitrary JavaScript execution in the browser': 'none',
    'JavaScript code execution in the context of the PhoneGap app': 'none',
    'Arbitrary file read from the Coldfusion install directory': 'none',
    'Arbitrary file system read': 'none',
    'Open Redirect attack': 'none',
    'Drive-by-download': 'none',
}
