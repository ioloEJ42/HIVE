# HIVE — Troubleshooting

## Installation issues

### "hive is not recognised as a command"
The virtual environment is not activated, or the install did not
complete. Try:
```
.venv\Scripts\activate        (Windows)
source .venv/bin/activate     (macOS / Linux)
pip install -e .
hive --version
```

If still not working:
```
python -m hive parse <file> -o <output>
```

### "python is not recognised" (Windows)
Python was not added to PATH. Reinstall Python from python.org and
tick "Add python.exe to PATH" on the first installer screen.

### "pip install fails" or permission errors
Run Command Prompt as Administrator, or contact IT.
On Linux/macOS: prefix with sudo (not recommended inside a venv).

### oletools deprecation warnings on startup
Lines like "PyparsingDeprecationWarning: 'enablePackrat' deprecated"
are warnings from inside the oletools library — not from HIVE.
They are harmless and do not affect macro detection. Ignore them.

## Parsing issues

### ".msg file fails to parse"
Some .msg files use non-standard OLE2 structures. HIVE will
log the error and produce partial output rather than crashing.
Check hive.log for the specific error. If the file is critical,
try opening it in Outlook and saving as .eml for re-analysis.

### "Email parses but body is empty"
Some emails use Content-Transfer-Encoding types that are unusual.
Check body.html.txt — the HTML body may be present even if the
plain text body is not. HIVE will use the HTML body as a fallback
for body.txt in this case.

### "No URLs found" but I can see URLs in the email
The URLs may be inside an attachment rather than the body.
Check urls.txt — HIVE labels each URL with its source.
If the email contains a PDF or Office document, the URLs should
appear under attachment:<filename>.

### "Auth results all show NONE"
The email has no stamped authentication headers. This can happen
with emails exported directly from an inbox without going through
a mail server (e.g. saved from Outlook before delivery). HIVE
reads only headers already present — it does not perform live
DNS lookups.

## Attachment issues

### "Attachment shows ⚠ ENCRYPTED"
The attachment is password-protected. HIVE cannot extract its
contents. Record the hash from hashes.csv and note the filename.
The password may be in the email body — check body.txt.

### "Attachment shows ⚠ IMAGE — CHECK FOR QR CODE"
HIVE detected an image file. It cannot decode QR codes automatically.
Open the image manually in an image viewer and check for QR codes.
The image hash is recorded in hashes.csv for evidence.

### "Macro scan shows unknown"
The file type is not eligible for macro scanning (e.g. PDF, TXT).
For Office documents, if this appears, the macro scan may have
encountered an error — check hive.log for details.

### "ZIP contents not extracted"
Either the ZIP is encrypted (check for ⚠ ENCRYPTED in summary.txt)
or the ZIP triggered a size/count limit (check hive.log for
ZIP bomb protection warnings). HIVE limits ZIP extraction to 100 files,
50 MB total uncompressed size, and 20 MB per file. Nested ZIPs beyond
--max-depth are also skipped.

## Integrity verification

### Verify HIVE has not been tampered with
```
hive verify
```

### Update the manifest after a new release
```
hive verify --update
```

### "Manifest not found"
The manifest has not been generated yet. Run:
```
hive verify --update
```
Then commit hive/MANIFEST.sha256 to version control.

### "N files MODIFIED"
The listed files have changed since the manifest was generated.
If this is unexpected, do not use the tool until the changes
are reviewed. If you made intentional changes, regenerate:
```
hive verify --update
```

### "N files MISSING"
Source files in the manifest are no longer on disk.
This may indicate tampering or an incomplete installation.
Reinstall HIVE from the repository.

### "N new files (not in manifest)"
Files exist on disk that were not present when the manifest
was generated. This is informational — not a failure.
If unexpected, review the new files before use.
