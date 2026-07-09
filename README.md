# HIVE

**Header, Indicator & Vector Examiner** — an offline email forensics and triage tool for hospital security teams.

HIVE parses `.eml` and `.msg` files and produces structured forensic output including headers, authentication analysis, body content, URLs, hashes, and attachments.

## Requirements

- Python 3.10+
- See `requirements.txt` for pinned dependencies

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Parse a single email file
hive parse sample.eml

# Parse all .eml and .msg files in a directory
hive parse /path/to/emails/ -o ./hive_output

# Options
hive parse sample.msg --no-extract --flat --max-depth 5 --max-size 100 --verbose
```

## Output Structure

```
hive_output/
└── <source_filename>/
    ├── summary.txt
    ├── hive.log
    ├── headers.txt
    ├── auth_analysis.txt
    ├── body.txt
    ├── body.html.txt
    ├── urls.txt
    ├── hashes.csv
    ├── attachments/
    └── nested_001/
```

## Security Notes

- Parses attacker-controlled content; all attachment filenames are sanitised before writing to disk.
- Pure Python parsers only — no network calls, no shell execution, no Office application invocation.
- Offline-capable; no API calls in V1.

## License

TBD
