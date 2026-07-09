#!/usr/bin/env python3
"""Generate a synthetic PDF attachment and sample .eml for HIVE tests."""

from __future__ import annotations

import base64
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent / "samples"
PDF_PATH = SAMPLES_DIR / "test_attachment.pdf"
EML_PATH = SAMPLES_DIR / "pdf_attachment.eml"

PDF_TEXT = (
    "Please review the following document and click the link to proceed:\n"
    "https://malicious-pdf-link.com/payload?id=9921\n"
    "For support contact: http://pdf-support.net/help"
)


def _build_pdf_by_hand(text: str) -> bytes:
    """Build a minimal single-page PDF containing plain text as raw bytes."""
    lines = text.split("\n")
    text_ops: list[str] = []
    y_position = 750
    for line in lines:
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        text_ops.append(f"BT /F1 12 Tf 50 {y_position} Td ({escaped}) Tj ET")
        y_position -= 18

    stream = "\n".join(text_ops) + "\n"
    stream_bytes = stream.encode("latin-1", errors="replace")
    parts: list[bytes] = []

    def add(content: str) -> None:
        parts.append(content.encode("latin-1"))

    add("%PDF-1.4\n")
    offsets = [0]

    def add_object(number: int, body: str) -> None:
        offsets.append(sum(len(part) for part in parts))
        add(f"{number} 0 obj\n{body}\nendobj\n")

    add_object(1, "<< /Type /Catalog /Pages 2 0 R >>")
    add_object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add_object(
        3,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        "/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    )
    add_object(4, f"<< /Length {len(stream_bytes)} >>\nstream\n{stream}endstream")
    add_object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    xref_position = sum(len(part) for part in parts)
    add("xref\n0 6\n")
    add("0000000000 65535 f \n")
    for offset in offsets[1:]:
        add(f"{offset:010d} 00000 n \n")
    add("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n")
    add(f"{xref_position}\n%%EOF\n")
    return b"".join(parts)


def _try_reportlab_pdf(text: str) -> bytes | None:
    """Return PDF bytes from reportlab when installed; otherwise None."""
    try:
        from io import BytesIO

        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError:
        return None

    buffer = BytesIO()
    pdf_canvas = canvas.Canvas(buffer, pagesize=letter)
    y_position = 750
    for line in text.split("\n"):
        pdf_canvas.drawString(50, y_position, line)
        y_position -= 18
    pdf_canvas.save()
    return buffer.getvalue()


def _try_pypdf_pdf(text: str) -> bytes | None:
    """Attempt PDF creation with pypdf PdfWriter.

    pypdf can assemble PDF structure but does not provide a simple API for
    placing arbitrary plain text on a page, so this returns None and the
    hand-written fallback is used instead.
    """
    try:
        from pypdf import PdfWriter
    except ImportError:
        return None

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    # Blank page only — no text API available without additional tooling.
    del writer, text
    return None


def create_pdf_bytes(text: str) -> bytes:
    """Create PDF bytes using the best available method."""
    pdf_bytes = _try_reportlab_pdf(text)
    if pdf_bytes is not None:
        return pdf_bytes

    _try_pypdf_pdf(text)
    return _build_pdf_by_hand(text)


def create_eml(pdf_bytes: bytes) -> str:
    """Build a synthetic phishing .eml with the PDF attached as base64."""
    encoded_pdf = base64.b64encode(pdf_bytes).decode("ascii")
    wrapped_pdf = "\r\n".join(
        encoded_pdf[index : index + 76] for index in range(0, len(encoded_pdf), 76)
    )

    return f"""Return-Path: <reports@quarterly-docs.com>
Received: from mail.quarterly-docs.com (mail.quarterly-docs.com [198.51.100.44])
        by mx1.protection.outlook.com with SMTP id q9si8821345qkd
        for <finance@vunhst.nhs.uk>; Tue, 12 Mar 2024 09:15:33 +0000
Received: from localhost (localhost [127.0.0.1])
        by mail.quarterly-docs.com with ESMTP id r1s2t3u4v5
        for <finance@vunhst.nhs.uk>; Tue, 12 Mar 2024 09:15:29 +0000
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
Subject: Q1 Financial Report - Review Required
Date: Tue, 12 Mar 2024 09:15:33 +0000
Message-ID: <20240312091533.q9si8821345@mail.quarterly-docs.com>
MIME-Version: 1.0
X-Mailer: SendGrid
X-Originating-IP: 198.51.100.44
Content-Type: multipart/mixed; boundary="=_HIVE_PDF_BOUNDARY_001"

--=_HIVE_PDF_BOUNDARY_001
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Dear Finance Team,

Please find attached the Q1 financial report for your review.

If the attachment does not open, use this link:
https://quarterly-docs.com/report?ref=Q12024

Regards,
Quarterly Reports Team

--=_HIVE_PDF_BOUNDARY_001
Content-Type: application/pdf
Content-Disposition: attachment; filename="report.pdf"
Content-Transfer-Encoding: base64

{wrapped_pdf}

--=_HIVE_PDF_BOUNDARY_001--
"""


def main() -> None:
    """Generate the PDF and .eml test fixtures."""
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    pdf_bytes = create_pdf_bytes(PDF_TEXT)
    PDF_PATH.write_bytes(pdf_bytes)

    eml_content = create_eml(pdf_bytes)
    EML_PATH.write_text(eml_content, encoding="utf-8", newline="\n")

    print(f"Created PDF: {PDF_PATH} ({len(pdf_bytes)} bytes)")
    print(f"Created EML: {EML_PATH} ({EML_PATH.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
