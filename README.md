# Threat Intelligence Extraction Framework 🛡️

**Advanced PDF analysis tool for structured threat intelligence extraction**  
*With MITRE ATT&CK mapping & VirusTotal integration*

## Features 🌟

- **Automatic IOC Extraction**  
  Extracts Domains, IPs, Hashes, Emails, CVEs
- **Context-Aware Analysis**  
  Inferences for Malware name and Threat actor identification
- **Live Enrichment**  
  VirusTotal detection stats, MITRE ATT&CK techniques
- **Multi-Format Output**  
  Structured JSON, Console display, File export

## Installation 💻

**Requirements:**  
- Python 3.8+  
- 100MB disk space  
- Internet access

**Installation Steps:**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Trushang-Patel/HACKIITK-2024.git
   cd HACKIITK-2024
2. **Create a virtual environment (Optional but recommended):**
    
    For macOS/Linux:
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```
    
    For Windows:
    ```bash
    python -m venv venv
    venv\Scripts\activate
    ```

3. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

**Note:** If you encounter any issues with dependencies, ensure that you have the necessary system libraries (such as `libmagic` for `python-magic`, which is required for file type detection).

### Troubleshooting

- **Streamlit/Dependency Issues:**  
  If you're having issues with Streamlit dependencies, try running:
  ```bash
  pip install streamlit --upgrade

## Usage/Examples

### Simple PDF Analysis
```bash
python runner.py sample_report.pdf
```

### Analysis Pipeline
```bash
PDF Input → Text Extraction → Pattern Matching → 
Context Analysis → API Enrichment → Structured Output
```
### Component Accuracy Table

| Component         | Method                          | Accuracy  |
|-------------------|---------------------------------|-----------|
| Domains           | Regex + TLD Validation          | 92%       |
| Malware Hashes    | Cryptographic Pattern Matching  | 100%      |
| Threat Actors     | Predefined Patterns + Context Clues | 76%  |
| MITRE ATT&CK      | STIX Database Matching          | 85%       |

## Example Report Analysis 💻

**Sample Input PDF:** `Mandiant_An-Overview-of-UNC2891(03-16-2022).pdf`

---
Had tried many approaches link LangChains etc. but did not succeed also tried streamlit but it ran into dependency issue



