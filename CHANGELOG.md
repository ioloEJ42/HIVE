# Changelog

All notable changes to HIVE will be documented in this file.
Semantic versioning is used: MAJOR.MINOR.PATCH

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.2.0] - 2026-07-09

### Added

- **Analyst attribution** — analyst username (from environment) and hostname recorded in hive.log and summary.txt for chain of custody
- **Password-protected attachment detection** — ZIP (bit flag), PDF (/Encrypt), Office Open XML (EncryptedPackage), legacy OLE2; flagged in summary.txt and hashes.csv before VBA scan is attempted
- **Image attachment flagging** — PNG, JPEG, GIF, BMP, WEBP, TIFF detected via content-type, extension, and magic bytes; flagged with QR code advisory in summary.txt
- **ZIP extraction** — recursive content analysis via stdlib zipfile; URL extraction from contained documents; macro and image detection on ZIP entries; nested ZIP recursion up to max_depth; ZIP bomb protection (100 file / 50MB total / 20MB per file limits); contents written to attachments/zip_contents/<name>/; source labels show attachment:<zip>/zip:<entry>
- **iocs.json** — structured machine-readable IOC export per email level; contains analyst/host attribution, email metadata, authentication results, defanged URLs with shortener/punycode/homoglyph flags, extracted domains and IPs, attachment hashes, and warnings; ensure_ascii=False preserves Unicode characters
- **Integrity verification** — `hive verify` checks SHA256 hashes of all 17 source files against hive/MANIFEST.sha256; `hive verify --update` regenerates the manifest at release time; detects modified, missing, and new files
- **QUICKSTART.md** — one-page analyst command reference
- **INSTALL.md** — step-by-step Windows installation guide
- **TROUBLESHOOTING.md** — common issues covering installation, parsing, attachments, output, performance, and integrity verification

### Changed

- hashes.csv has_macros column gains two new values: "encrypted" and "image" (alongside existing yes/no/unknown)
- summary.txt ATTACHMENTS section shows ⚠ ENCRYPTED and ⚠ IMAGE — CHECK FOR QR CODE flags
- summary.txt includes Analyst and Host fields in the header block
- hive.log entries include analyst username

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
