# HIVE — Quick Start

## Install (first time only)

### macOS / Linux
```
git clone <repo url>
cd HIVE
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Windows
```
git clone <repo url>
cd HIVE
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

## Run

### Single email
```
hive parse suspicious.eml -o ./output
```

### Batch (folder of emails)
```
hive parse ./inbox/ -o ./output
```

### Skip writing attachments to disk
```
hive parse suspicious.eml -o ./output --no-extract
```

### Do not recurse into nested emails
```
hive parse suspicious.eml -o ./output --flat
```

### Check version
```
hive --version
```

## Output files (open in this order)

```
summary.txt        — analyst-ready overview, warnings, all IOCs
iocs.json          — machine-readable IOC export
auth_analysis.txt  — SPF / DKIM / DMARC / ARC results
headers.txt        — verbatim raw headers
urls.txt           — all URLs, defanged, with source labels
hashes.csv         — attachment hashes (MD5 / SHA1 / SHA256)
body.txt           — plain text body
body.html.txt      — raw HTML body (DO NOT open in browser)
hive.log           — audit log with analyst name and timestamp
attachments/       — extracted attachment files
nested_001/        — output for embedded emails (same structure)
```

## Flags

```
--no-extract    Skip writing attachments to disk
--flat          Do not recurse into nested emails
--max-depth N   Max nested email depth (default: 10)
--max-size N    Max input file size in MB (default: 50)
--verbose       Show warnings in terminal output
--version       Print version and exit
```

## What HIVE flags automatically

```
⚠ SPF / DKIM / DMARC fail
⚠ Reply-To domain mismatch
⚠ Macros detected in Office attachment
⚠ Encrypted / password-protected attachment
⚠ Image attachment (may contain QR code)
⚠ URL shortener (destination unknown)
⚠ Punycode domain (decoded form shown)
⚠ Homoglyph / mixed-script domain (Unicode codepoint shown)
⚠ URLs found inside ZIP, PDF, DOCX, XLSX, PPTX, RTF attachments
```
