#!/usr/bin/env python3
"""Generate a synthetic ZIP attachment and sample .eml for HIVE tests."""

from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent / "samples"
ZIP_PATH = SAMPLES_DIR / "test_attachment.zip"
EML_PATH = SAMPLES_DIR / "zip_attachment.eml"

DOCUMENT_TXT = (
    "Visit https://malicious-zip-link.com/payload for details\n"
    "Support: http://zip-support.net/help"
)
README_TXT = "This is a readme file with no URLs."
INNER_TXT = "Nested content: https://nested-zip-link.com/deep"


def _build_nested_zip() -> bytes:
    """Build a nested ZIP containing inner.txt."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("inner.txt", INNER_TXT)
    buffer.seek(0)
    return buffer.read()


def create_zip(path: Path) -> bytes:
    """Write test_attachment.zip with txt files and a nested archive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    nested_zip = _build_nested_zip()

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("document.txt", DOCUMENT_TXT)
        archive.writestr("readme.txt", README_TXT)
        archive.writestr("nested.zip", nested_zip)
    buffer.seek(0)
    zip_bytes = buffer.read()
    path.write_bytes(zip_bytes)
    return zip_bytes


def _wrap_base64(data: bytes) -> str:
    """Encode bytes as base64 with RFC 2045 line wrapping."""
    encoded = base64.b64encode(data).decode("ascii")
    return "\r\n".join(encoded[index : index + 76] for index in range(0, len(encoded), 76))


def create_eml(zip_bytes: bytes) -> str:
    """Build a synthetic phishing .eml with the ZIP attached as base64."""
    wrapped_zip = _wrap_base64(zip_bytes)

    return f"""Return-Path: <reports@quarterly-docs.com>
Received: from mail.quarterly-docs.com (mail.quarterly-docs.com [198.51.100.44])
        by mx1.protection.outlook.com with SMTP id r2si1043567qkd
        for <finance@vunhst.nhs.uk>; Thu, 14 Mar 2024 11:00:04 +0000
Received: from localhost (localhost [127.0.0.1])
        by mail.quarterly-docs.com with ESMTP id t3u4v5w6x7
        for <finance@vunhst.nhs.uk>; Thu, 14 Mar 2024 11:00:00 +0000
Received-SPF: fail (domain of reports@quarterly-docs.com does not designate
        198.51.100.44 as permitted sender)
        receiver=mx1.protection.outlook.com;
        client-ip=198.51.100.44;
        helo=mail.quarterly-docs.com
Authentication-Results: mx1.protection.outlook.com;
        dmarc=fail action=none header.from=quarterly-docs.com;
        spf=fail smtp.mailfrom=reports@quarterly-docs.com;
        dkim=none
From: "Quarterly Reports" <reports@quarterly-docs.com>
Reply-To: reports@quarterly-docs.com
To: finance@vunhst.nhs.uk
Subject: Q1 Archive - Review Required
Date: Thu, 14 Mar 2024 11:00:00 +0000
Message-ID: <20240314110000.zip1043567@mail.quarterly-docs.com>
MIME-Version: 1.0
X-Mailer: SendGrid
X-Originating-IP: 198.51.100.44
Content-Type: multipart/mixed; boundary="=_HIVE_ZIP_BOUNDARY_001"

--=_HIVE_ZIP_BOUNDARY_001
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Dear Finance Team,

Please find attached the Q1 archive for your review.

If the attachment does not open, use this link:
https://quarterly-docs.com/zip-report?ref=Q12024

Regards,
Quarterly Reports Team

--=_HIVE_ZIP_BOUNDARY_001
Content-Type: application/zip
Content-Disposition: attachment; filename="archive.zip"
Content-Transfer-Encoding: base64

{wrapped_zip}

--=_HIVE_ZIP_BOUNDARY_001--
"""


def main() -> None:
    """Generate the ZIP and .eml test fixtures."""
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    zip_bytes = create_zip(ZIP_PATH)
    EML_PATH.write_text(create_eml(zip_bytes), encoding="utf-8", newline="\n")

    print(f"Created ZIP: {ZIP_PATH} ({len(zip_bytes)} bytes)")
    print(f"Created EML: {EML_PATH} ({EML_PATH.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
