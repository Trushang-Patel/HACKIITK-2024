import re
import json
import fitz
import requests
from collections import defaultdict
from typing import Dict, List



# Configuration
with open('config.json') as f:
    config = json.load(f)
VIRUSTOTAL_API_KEY = config["virustotal_api_key"]
VT_API_URL = "https://www.virustotal.com/api/v3/files/"
MITRE_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

ALLOWED_TLDS = {
    'com', 'in', 'ru', 'info', 'org', 'net', 'gov', 
    'edu', 'mil', 'co', 'uk', 'us', 'biz', 'name', 
    'mobi', 'xyz', 'site', 'online', 'io', 'ai', 'ca',
    'de', 'fr', 'jp', 'cn', 'eu', 'asia', 'app', 'dev'
}

PATTERNS = {
    'domain': r'\b(?:[a-zA-Z0-9-]+(?:\[\.\]|\.))+(?:[a-zA-Z]{2,})\b',
    'hash': r'\b[a-fA-F0-9]{32,64}\b',
    'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'malware': r'\b([A-Z][a-zA-Z0-9]+(?:RAT|Bot|Stealer|Wiper|Loader|Snake|Beacon|Payload))\b',
    'threat_actor': r'\b(?:APT\d+|UNC\d+|group\d+|team\d+|attacker\d+|campaign\d+|TA\d+|FIN\d+|Transparent Tribe|Ghostwriter|Sandworm)\b',
    'cve': r'\bCVE-\d{4}-\d{4,7}\b'
}

def normalize_domain(domain: str) -> str:
    """Normalize domain to handle different representations"""
    return domain.replace('[.]', '.').lower().strip()

def is_valid_domain(domain: str) -> bool:
    """Validate domain structure and TLD"""
    parts = domain.split('.')
    return len(parts) >= 2 and parts[-1] in ALLOWED_TLDS

def extract_text_from_pdf(pdf_path: str) -> str:
    """General PDF text extraction"""
    text = ""
    with fitz.open(pdf_path) as doc:
        for page in doc:
            text += page.get_text()
    return text

def check_virustotal(file_hash: str) -> Dict:
    """Get VirusTotal analysis results"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(f"{VT_API_URL}{file_hash}", headers=headers)
        if response.status_code == 200:
            return {
                'malicious': response.json()['data']['attributes']['last_analysis_stats']['malicious'],
                'total': sum(response.json()['data']['attributes']['last_analysis_stats'].values()),
                'permalink': f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        return {'malicious': 0, 'total': 0, 'permalink': ''}
    except Exception as e:
        return {'error': str(e)}

def detect_malware_context(text: str, hash_value: str) -> str:
    """Detect associated malware from context"""
    context = text.lower()[max(0, text.find(hash_value)-200):text.find(hash_value)+200]
    for malware in re.findall(PATTERNS['malware'], context, re.IGNORECASE):
        base_name = re.sub(r'(?i)(RAT|Bot|Stealer|Wiper|Loader|Snake|Beacon|Payload)$', '', malware[0]).strip()
        if base_name:
            return base_name.title()
    return 'Unknown'

def map_to_mitre(text: str, stix_data: List[Dict]) -> Dict:
    """Dynamic MITRE ATT&CK mapping with validation"""
    mappings = defaultdict(list)
    text_lower = text.lower()
    
    valid_mitre_ids = set()
    for entry in stix_data:
        if 'external_references' in entry:
            for ref in entry['external_references']:
                if ref.get('source_name') == 'mitre-attack':
                    valid_mitre_ids.add(ref['external_id'])

    for technique in stix_data:
        if technique['type'] == 'attack-pattern':
            tech_name = technique['name'].lower()
            if tech_name in text_lower:
                mitre_id = next((ref['external_id'] for ref in technique.get('external_references', []) 
                               if ref.get('source_name') == 'mitre-attack'), None)
                if mitre_id and mitre_id in valid_mitre_ids:
                    mappings['techniques'].append([mitre_id, technique['name']])
        
        elif technique['type'] == 'x-mitre-tactic':
            tactic_name = technique['name'].lower()
            if tactic_name in text_lower:
                mitre_id = next((ref['external_id'] for ref in technique.get('external_references', []) 
                               if ref.get('source_name') == 'mitre-attack'), None)
                if mitre_id and mitre_id in valid_mitre_ids:
                    mappings['tactics'].append([mitre_id, technique['name']])
    
    # Deduplicate while preserving order
    seen = set()
    mappings['tactics'] = [x for x in mappings['tactics'] if not (x[0] in seen or seen.add(x[0]))]
    seen = set()
    mappings['techniques'] = [x for x in mappings['techniques'] if not (x[0] in seen or seen.add(x[0]))]
    
    return mappings

def analyze_report(text: str) -> Dict:
    """Advanced analysis with context-aware processing"""
    results = {
        'IoCs': defaultdict(list),
        'TTPs': {'Tactics': [], 'Techniques': []},
        'Threat Actor(s)': [],
        'Malware': [],
        'Targeted Entities': []
    }

    # Domain processing
    seen_domains = set()
    for domain in re.findall(PATTERNS['domain'], text, re.IGNORECASE):
        normalized = normalize_domain(domain)
        if is_valid_domain(normalized) and normalized not in seen_domains:
            results['IoCs']['Domains'].append(normalized)
            seen_domains.add(normalized)

    # IP address processing
    results['IoCs']['IP addresses'] = list(set(re.findall(PATTERNS['ipv4'], text)))

    # Threat Actor processing
    threat_actors = set()
    for actor in re.findall(PATTERNS['threat_actor'], text, re.IGNORECASE):
        normalized = re.sub(r'\s+', ' ', actor.strip()).title()
        threat_actors.add(normalized)
    results['Threat Actor(s)'] = list(threat_actors)

    # Malware and Hash processing
    malware_hashes = defaultdict(list)
    for hash_value in set(re.findall(PATTERNS['hash'], text)):
        vt_results = check_virustotal(hash_value)
        malware_name = detect_malware_context(text, hash_value)
        entry = {
            'value': hash_value,
            'type': 'md5' if len(hash_value) == 32 else
                    'sha1' if len(hash_value) == 40 else
                    'sha256' if len(hash_value) == 64 else 'unknown',
            'vt_results': vt_results
        }
        malware_hashes[malware_name].append(entry)

    # Build malware entries
    for malware_name, hashes in malware_hashes.items():
        malware_entry = {'Name': malware_name, 'tags': []}
        for h in hashes:
            malware_entry[h['type']] = h['value']
            if h['vt_results'].get('malicious', 0) > 0:
                malware_entry['tags'].append(f"Detected by {h['vt_results']['malicious']}/92 engines")
        results['Malware'].append(malware_entry)

    # Target processing
    targets = set()
    for match in re.finditer(r'(targeting|against|victims? of|attacks? on)\s([A-Z][a-zA-Z\s]+)', text, re.IGNORECASE):
        target = re.sub(r'\s+', ' ', match.group(2).strip())
        targets.add(target)
    results['Targeted Entities'] = list(targets)

    # MITRE ATT&CK Mapping
    try:
        stix_data = requests.get(MITRE_ENTERPRISE_URL).json()['objects']
        mitre_mappings = map_to_mitre(text, stix_data)
        results['TTPs']['Tactics'] = mitre_mappings.get('tactics', [])
        results['TTPs']['Techniques'] = mitre_mappings.get('techniques', [])
    except Exception as e:
        print(f"MITRE mapping failed: {str(e)}")

    return results

def process_pdf(pdf_path: str) -> Dict:
    """Full processing pipeline with JSON output"""
    text = extract_text_from_pdf(pdf_path)
    analysis = analyze_report(text)
    
    with open('threat_intel_report.json', 'w') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
    
    return analysis

if __name__ == "__main__":
    report = process_pdf('RecordedFuture_mtp-2022-0302(03-02-2022).pdf')
    print(json.dumps(report, indent=2))