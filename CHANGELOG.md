# Changelog

All notable changes to HIVE will be documented in this file.
Semantic versioning is used: MAJOR.MINOR.PATCH

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.1.0] - 2026-07-09

### Added

- **URL shortener detection** — flags URLs using 40+ known shortener domains (bit.ly, tinyurl.com, t.co etc.) with a warning in urls.txt and summary.txt; destination marked as unknown
- **Punycode domain detection** — identifies xn-- encoded domains and decodes them to their human-readable Unicode form; both forms shown in output
- **Homoglyph / mixed-script detection** — detects non-ASCII and mixed-script characters in domains using Python unicodedata stdlib; flags Cyrillic, Greek, Arabic, Armenian, and Georgian characters mixed with Latin script; reports exact character name and codepoint (e.g. а U+0430 CYRILLIC SMALL LETTER A); no third-party dependencies

### Changed

- urls.txt now includes indented warning annotations beneath flagged URLs (shortener, punycode, homoglyph)
- summary.txt WARNINGS section now includes URL-level warnings alongside email-level parser warnings
- UrlFinding dataclass extended with is_shortener, is_punycode, and homoglyph_detail fields

## [1.0.0] - 2026-07-09

### Added

- **CLI** (`hive parse`) — single-file and batch directory processing with `--output`, `--no-extract`, `--flat`, `--max-depth`, `--max-size`, `--verbose`, and `--version` flags
- **`.eml` parser** — RFC 5322 parsing via Python `email` module; MIME multipart handling; base64 and quoted-printable decoding; nested `message/rfc822` recursion; Reply-To domain mismatch detection; input file hashing (MD5, SHA1, SHA256)
- **`.msg` parser** — Outlook `.msg` parsing via `extract-msg`; equivalent `ParsedEmail` output to the EML path
- **Header extraction** — verbatim `headers.txt` output; Received-hop chain parsing (oldest-first); URL defanging (`hxxp`/`hxxps`, `[.]` dot notation, bare IP defanging)
- **Authentication analysis** — SPF, DKIM, DMARC, and ARC result extraction from `Authentication-Results` and `Received-SPF` headers; human-readable `auth_analysis.txt` output; no live DNS lookups
- **Body extraction** — plain-text `body.txt`; HTML-to-text fallback with script/style stripping; `body.html.txt` with safety header warning analysts not to open in a browser
- **URL extraction** — URLs from plain text, HTML (href/src), and attachment content (PDF, DOCX, XLSX, PPTX, RTF, TXT); source labels (`body:plain`, `body:html`, `attachment:<filename>`, nested depth labels); all URLs defanged in output
- **Attachment handling** — extraction to `attachments/`; MD5, SHA1, SHA256 hashing; `hashes.csv` output; filename sanitisation (path traversal, reserved names, unsafe characters, length limits); VBA macro detection on Office documents via oletools
- **Forensic output writer** — per-email directory structure with `summary.txt`, `headers.txt`, `auth_analysis.txt`, `body.txt`, `body.html.txt`, `urls.txt`, `hashes.csv`, `hive.log`, and `attachments/`; recursive `nested_NNN/` subdirectories for embedded emails; output directory collision handling (`_1`, `_2`, … suffixes)
- **Batch processing** — `process_directory()` for folders of `.eml`/`.msg` files; ignores non-email files; graceful failure for invalid paths
- **Audit logging** — `hive.log` with UTC timestamps per processed email
- **Safety controls** — no network calls in V1; no shell execution; configurable max recursion depth and max input file size; `--no-extract` mode (hashes only, no attachment files on disk)
- **Test suite** — 194 tests across 28 groups using nine synthetic `.eml` samples covering parsing, nested emails, attachments, malformed headers, HTML-only bodies, defanging, filename sanitisation, batch processing, output collision, evidence integrity, auth text formatting, and URL extraction from PDF, DOCX, XLSX, PPTX, and RTF attachment types; fixture generator scripts included for all synthetic document samples
