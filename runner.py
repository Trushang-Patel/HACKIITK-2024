import re
import json
import fitz
import requests
from collections import defaultdict
from typing import Dict, List

VIRUSTOTAL_KEY = "1bfd46d0f94a69d3e7b9f314094de63218d0d293891aa5926df514aeff56f736"
VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/files/"
MITRE_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

ALLOWED_TOP_LEVEL_DOMAINS = {
    'com', 'in', 'ru', 'info', 'org', 'net', 'gov', 
    'edu', 'mil', 'co', 'uk', 'us', 'biz', 'name', 
    'mobi', 'xyz', 'site', 'online', 'io', 'ai', 'ca',
    'de', 'fr', 'jp', 'cn', 'eu', 'asia', 'app', 'dev'
}

PATTERN_REGEXES = {
    'domain': r'\b(?:[a-zA-Z0-9-]+(?:\[\.\]|\.))+(?:[a-zA-Z]{2,})\b',
    'hash': r'\b[a-fA-F0-9]{32,64}\b',
    'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'malware': r'\b([A-Z][a-zA-Z0-9]+(?:RAT|Bot|Stealer|Wiper|Loader|Snake|Beacon|Payload))\b',
    'threat_actor': r'\b(?:APT\d+|UNC\d+|group\d+|team\d+|attacker\d+|campaign\d+|TA\d+|FIN\d+|Transparent Tribe|Ghostwriter|Sandworm)\b',
    'cve': r'\bCVE-\d{4}-\d{4,7}\b'
}

def clean_and_format_domain(domain: str) -> str:
    """Format domain to standardize different variations"""
    return domain.replace('[.]', '.').lower().strip()

def validate_domain_structure(domain: str) -> bool:
    """Ensure the domain follows correct format and has a valid TLD"""
    parts = domain.split('.')
    return len(parts) >= 2 and parts[-1] in ALLOWED_TOP_LEVEL_DOMAINS

def extract_text_from_pdf_file(pdf_path: str) -> str:
    """Extract raw text from the given PDF file"""
    extracted_text = ""
    with fitz.open(pdf_path) as pdf_document:
        for page in pdf_document:
            extracted_text += page.get_text()
    return extracted_text

def query_virustotal_for_file(file_hash: str) -> Dict:
    """Query VirusTotal for a file hash and retrieve its analysis results"""
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    try:
        response = requests.get(f"{VIRUS_TOTAL_URL}{file_hash}", headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats['malicious'],
                'total': sum(stats.values()),
                'link': f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        return {'malicious': 0, 'total': 0, 'link': ''}
    except Exception as e:
        return {'error': str(e)}

def identify_associated_malware_in_context(text: str, file_hash: str) -> str:
    """Identify the type of malware associated with a given file hash"""
    context = text.lower()[max(0, text.find(file_hash)-200):text.find(file_hash)+200]
    for malware in re.findall(PATTERN_REGEXES['malware'], context, re.IGNORECASE):
        base_name = re.sub(r'(?i)(RAT|Bot|Stealer|Wiper|Loader|Snake|Beacon|Payload)$', '', malware[0]).strip()
        if base_name:
            return base_name.title()
    return 'Unknown'

def associate_with_mitre_techniques(text: str, mitre_data: List[Dict]) -> Dict:
    """Map extracted content to MITRE ATT&CK TTPs"""
    mappings = defaultdict(list)
    lower_text = text.lower()
    
    valid_technique_ids = set()
    for entry in mitre_data:
        if 'external_references' in entry:
            for ref in entry['external_references']:
                if ref.get('source_name') == 'mitre-attack':
                    valid_technique_ids.add(ref['external_id'])

    for technique in mitre_data:
        if technique['type'] == 'attack-pattern':
            tech_name = technique['name'].lower()
            if tech_name in lower_text:
                mitre_id = next((ref['external_id'] for ref in technique.get('external_references', []) 
                               if ref.get('source_name') == 'mitre-attack'), None)
                if mitre_id and mitre_id in valid_technique_ids:
                    mappings['techniques'].append([mitre_id, technique['name']])
        
        elif technique['type'] == 'x-mitre-tactic':
            tactic_name = technique['name'].lower()
            if tactic_name in lower_text:
                mitre_id = next((ref['external_id'] for ref in technique.get('external_references', []) 
                               if ref.get('source_name') == 'mitre-attack'), None)
                if mitre_id and mitre_id in valid_technique_ids:
                    mappings['tactics'].append([mitre_id, technique['name']])
    
    # Remove duplicates while preserving order
    seen_techniques = set()
    mappings['tactics'] = [x for x in mappings['tactics'] if not (x[0] in seen_techniques or seen_techniques.add(x[0]))]
    seen_techniques = set()
    mappings['techniques'] = [x for x in mappings['techniques'] if not (x[0] in seen_techniques or seen_techniques.add(x[0]))]
    
    return mappings

def perform_report_analysis(text: str) -> Dict:
    """Comprehensive report analysis with advanced context-aware extraction"""
    analysis_results = {
        'Indicators_of_Compromise': defaultdict(list),
        'TTPs': {'Tactics': [], 'Techniques': []},
        'Threat_Actors': [],
        'Malware': [],
        'Targeted_Entities': []
    }

    # Domain extraction
    seen_domains = set()
    for domain in re.findall(PATTERN_REGEXES['domain'], text, re.IGNORECASE):
        formatted = clean_and_format_domain(domain)
        if validate_domain_structure(formatted) and formatted not in seen_domains:
            analysis_results['Indicators_of_Compromise']['Domains'].append(formatted)
            seen_domains.add(formatted)

    # IP extraction
    analysis_results['Indicators_of_Compromise']['IP_addresses'] = list(set(re.findall(PATTERN_REGEXES['ipv4'], text)))

    # Threat actor extraction
    threat_actors = set()
    for actor in re.findall(PATTERN_REGEXES['threat_actor'], text, re.IGNORECASE):
        formatted = re.sub(r'\s+', ' ', actor.strip()).title()
        threat_actors.add(formatted)
    analysis_results['Threat_Actors'] = list(threat_actors)

    # Malware and hash extraction
    malware_hashes = defaultdict(list)
    for hash_value in set(re.findall(PATTERN_REGEXES['hash'], text)):
        vt_data = query_virustotal_for_file(hash_value)
        malware_name = identify_associated_malware_in_context(text, hash_value)
        entry = {
            'value': hash_value,
            'type': 'md5' if len(hash_value) == 32 else
                    'sha1' if len(hash_value) == 40 else
                    'sha256' if len(hash_value) == 64 else 'unknown',
            'virustotal': vt_data
        }
        malware_hashes[malware_name].append(entry)

    # Construct malware entries
    for malware_name, hashes in malware_hashes.items():
        malware_entry = {'Name': malware_name, 'tags': []}
        for h in hashes:
            malware_entry[h['type']] = h['value']
            if h['virustotal'].get('malicious', 0) > 0:
                malware_entry['tags'].append(f"Detected by {h['virustotal']['malicious']}/92 engines")
        analysis_results['Malware'].append(malware_entry)

    # Target extraction
    targets = set()
    for match in re.finditer(r'(targeting|against|victims? of|attacks? on)\s([A-Z][a-zA-Z\s]+)', text, re.IGNORECASE):
        target = re.sub(r'\s+', ' ', match.group(2).strip())
        targets.add(target)
    analysis_results['Targeted_Entities'] = list(targets)

    # MITRE ATT&CK Mapping
    try:
        mitre_data = requests.get(MITRE_JSON_URL).json()['objects']
        mitre_mappings = associate_with_mitre_techniques(text, mitre_data)
        analysis_results['TTPs']['Tactics'] = mitre_mappings.get('tactics', [])
        analysis_results['TTPs']['Techniques'] = mitre_mappings.get('techniques', [])
    except Exception as e:
        print(f"MITRE mapping failed: {str(e)}")

    return analysis_results

def process_and_analyze_pdf(pdf_path: str) -> Dict:
    """Execute the entire processing pipeline for a PDF and output a JSON report"""
    text = extract_text_from_pdf_file(pdf_path)
    analysis = perform_report_analysis(text)
    
    with open('threat_intelligence_report.json', 'w') as json_file:
        json.dump(analysis, json_file, indent=2, ensure_ascii=False)
    
    return analysis

if __name__ == "__main__":
    report = process_and_analyze_pdf('RecordedFuture_mtp-2022-0302(03-02-2022).pdf')
    print(json.dumps(report, indent=2))
