# HIVE — Header, Indicator & Vector Examiner

HIVE is an offline email forensics and triage tool for security analysts. It parses `.eml` and `.msg` files and produces structured forensic output — headers, authentication results, body content, defanged URLs, attachment hashes, and extracted files — without making network calls. It is designed for phishing triage in NHS and hospital security teams who need repeatable, evidence-grade analysis on isolated workstations.

## What HIVE produces

```
hive_output/
└── email_filename/
    ├── headers.txt          # verbatim raw headers, untouched
    ├── auth_analysis.txt    # SPF / DKIM / DMARC / ARC results
    ├── body.txt             # plain text body
    ├── body.html.txt        # raw HTML body with safety header
    ├── urls.txt             # all URLs, defanged, with source labels
    ├── hashes.csv           # attachment hashes (MD5/SHA1/SHA256)
    ├── summary.txt          # analyst-ready forensic overview
    ├── hive.log             # audit log (UTC timestamps)
    └── attachments/         # extracted attachment files
        └── ...
    └── nested_001/          # recursive output for embedded emails
        └── ...              # same structure as above
```

## Features

- `.eml` and `.msg` parsing
- Recursive nested email handling (configurable depth)
- SPF / DKIM / DMARC / ARC header analysis (stamped headers, no DNS calls)
- URL extraction from email body AND attachments (PDF, DOCX, XLSX, PPTX, RTF, TXT)
- All URLs defanged by default (`hxxp`, `[.]` notation)
- Attachment extraction with MD5 / SHA1 / SHA256 hashing
- VBA macro detection on Office documents (oletools)
- Input file hashing for evidence integrity
- Batch processing (directory of emails)
- `--no-extract` flag (hashes only, no files written to disk)
- Offline capable — no network calls in V1
- Path traversal protection on all attachment filenames
- Audit log with UTC timestamps

## Installation

### Requirements

- Python 3.10 or newer
- pip

### macOS / Linux

```bash
git clone <repo url>
cd HIVE
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Windows (Command Prompt)

```cmd
git clone <repo url>
cd HIVE
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

Note: On Windows, if `hive` is not recognised after install, try:

```cmd
python -m hive parse <input>
```

## Usage

### Single file

```bash
hive parse suspicious.eml -o ./output
```

### Batch mode (directory)

```bash
hive parse ./inbox/ -o ./output
```

### Common flags

| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output` | `./hive_output` | Output directory |
| `--no-extract` | off | Skip writing attachments to disk |
| `--flat` | off | Do not recurse into nested emails |
| `--max-depth INT` | 10 | Maximum nested email recursion depth |
| `--max-size INT` | 50 | Maximum input file size in MB |
| `--verbose` | off | Verbose terminal output |
| `--version` | | Print version and exit |

### Example output (terminal)

```
✔  suspicious.eml
     Output      : ./hive_output/suspicious_email
     Attachments : 2  |  URLs : 5  |  Macros : 1
     Warnings    : 3
  ─────────────────────────────────────────
  HIVE complete — 1 processed, 0 failed
  ⚠  Macros detected in 1 attachment(s) — review hashes.csv
```

## Safety design

HIVE parses attacker-controlled email content and must be treated accordingly. All parsing uses pure Python libraries — nothing in the email body or attachments is executed, and no Office applications are invoked. V1 makes no network calls; authentication results are read from stamped headers only, with no live DNS lookups. Attachment filenames are sanitised before writing to disk to prevent path traversal. HTML bodies are saved as `.html.txt` with a safety header to reduce the risk of accidental browser execution. Recursion depth and input file size limits are enforced to contain resource abuse. Every input file is hashed (MD5, SHA1, SHA256) at parse time for evidence integrity.

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| extract-msg | 0.55.0 | Outlook `.msg` parsing |
| beautifulsoup4 | 4.13.5 | HTML parsing |
| pypdf | 6.14.2 | PDF text and URL extraction |
| python-docx | 1.2.0 | Word document URL extraction |
| openpyxl | 3.1.5 | Excel spreadsheet URL extraction |
| python-pptx | 1.0.2 | PowerPoint URL extraction |
| striprtf | 0.0.32 | RTF document text extraction |
| oletools | 0.60.2 | VBA macro detection |

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

132 tests across 23 groups covering parsing, extraction, authentication analysis, defanging, safety checks, batch processing, and evidence integrity.

## Version

1.0.0 — initial release
