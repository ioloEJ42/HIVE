#!/usr/bin/env python3
"""Generate a synthetic RTF attachment and sample .eml for HIVE tests."""

from __future__ import annotations

import base64
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent / "samples"
RTF_PATH = SAMPLES_DIR / "test_attachment.rtf"
EML_PATH = SAMPLES_DIR / "rtf_attachment.eml"

RTF_CONTENT = """{\\rtf1\\ansi\\deff0
{\\fonttbl{\\f0 Helvetica;}}
\\f0\\fs24
Please review the following report.\\par
Approval link: https://malicious-rtf-link.com/approve?id=5566\\par
For support visit: http://rtf-support.net/help\\par
}"""


def create_rtf(path: Path) -> bytes:
    """Write a minimal hand-built RTF document as UTF-8."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rtf_bytes = RTF_CONTENT.encode("utf-8")
    path.write_bytes(rtf_bytes)
    return rtf_bytes


def _wrap_base64(data: bytes) -> str:
    """Encode bytes as base64 with RFC 2045 line wrapping."""
    encoded = base64.b64encode(data).decode("ascii")
    return "\r\n".join(encoded[index : index + 76] for index in range(0, len(encoded), 76))


def create_eml(rtf_bytes: bytes) -> str:
    """Build a synthetic phishing .eml with the RTF attached as base64."""
    wrapped_rtf = _wrap_base64(rtf_bytes)

    return f"""Return-Path: <reports@quarterly-docs.com>
Received: from mail.quarterly-docs.com (mail.quarterly-docs.com [198.51.100.44])
        by mx1.protection.outlook.com with SMTP id r2si1043567qkd
        for <finance@vunhst.nhs.uk>; Thu, 14 Mar 2024 10:00:04 +0000
Received: from localhost (localhost [127.0.0.1])
        by mail.quarterly-docs.com with ESMTP id t3u4v5w6x7
        for <finance@vunhst.nhs.uk>; Thu, 14 Mar 2024 10:00:00 +0000
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
Subject: Q1 RTF Report - Review Required
Date: Thu, 14 Mar 2024 10:00:00 +0000
Message-ID: <20240314100000.rtf1043567@mail.quarterly-docs.com>
MIME-Version: 1.0
X-Mailer: SendGrid
X-Originating-IP: 198.51.100.44
Content-Type: multipart/mixed; boundary="=_HIVE_RTF_BOUNDARY_001"

--=_HIVE_RTF_BOUNDARY_001
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Dear Finance Team,

Please find attached the Q1 RTF report for your review.

If the attachment does not open, use this link:
https://quarterly-docs.com/rtf-report?ref=Q12024

Regards,
Quarterly Reports Team

--=_HIVE_RTF_BOUNDARY_001
Content-Type: application/rtf
Content-Disposition: attachment; filename="report.rtf"
Content-Transfer-Encoding: base64

{wrapped_rtf}

--=_HIVE_RTF_BOUNDARY_001--
"""


def main() -> None:
    """Generate the RTF and .eml test fixtures."""
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    rtf_bytes = create_rtf(RTF_PATH)
    EML_PATH.write_text(create_eml(rtf_bytes), encoding="utf-8", newline="\n")

    print(f"Created RTF: {RTF_PATH} ({len(rtf_bytes)} bytes)")
    print(f"Created EML: {EML_PATH} ({EML_PATH.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
