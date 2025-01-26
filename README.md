# Threat Intelligence Extraction Framework 🛡️

**Advanced PDF analysis tool for structured threat intelligence extraction**  
*With MITRE ATT&CK mapping & VirusTotal integration*

## Features 🌟

- **Automatic IOC Extraction**  
  Domains • IPs • Hashes • Emails • CVEs
- **Context-Aware Analysis**  
  Malware name inference • Threat actor identification
- **Live Enrichment**  
  VirusTotal detection stats • MITRE ATT&CK techniques
- **Multi-Format Output**  
  Structured JSON • Console display • File export

## Installation 💻

**Requirements:** Python 3.8+ • 100MB disk space • Internet access

```bash
# Clone repository
git clone https://github.com/Trushang-Patel/HACKIITK-2024.git
cd HACKIITK-2024

# Install dependencies
pip install -r requirements.txt
```
## Usage/Examples

```bash
python runner.py sample_report.pdf
```
OR Explicitely change in line 192 of runner.py

## Analysis Pipeline

```bash
PDF Input → Text Extraction → Pattern Matching → 
Context Analysis → API Enrichment → Structured Output
```
| Component |  Method  | Accuracy |
|:-----|:--------:|------:|
| Domains   | Regex + TLD Validation | 92% |
| Malware Hashes   |  Cryptographic Pattern Matching  |   100% |
| Threat Actors   | Predefined Patterns + Context Clues	 |    76% |
| MITRE ATT&CK   | STIX Database Matching |    85% |

## Example Report Analysis 💻

**Sample Input PDF:** Mandiant_An-Overview-of-UNC2891(03-16-2022).pdf

Had tried many approaches link LangChains etc. but did not succeed also tried streamlit but it ran into dependency issue
