"""Email header extraction and hop-chain analysis for HIVE.

Produces verbatim header output for headers.txt and parses Received: headers
into a structured hop chain for summary.txt. Also provides defanging utilities
used by the output writer and other extractors.
"""

from __future__ import annotations

import logging
import re

from hive.parser.common import ParsedEmail

logger = logging.getLogger(__name__)

# First token after "from " — hostname before optional parenthesis or semicolon
_FROM_HOST_RE = re.compile(r"from\s+<?([^>\s(;]+)>?", re.IGNORECASE)

# IPv4 inside square brackets, e.g. [192.168.1.1]
_FROM_IP_BRACKET_RE = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")

# Bare IPv4 address anywhere in the header value
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# First token after "by " — receiving host
_BY_HOST_RE = re.compile(r"by\s+<?([^>\s;]+)>?", re.IGNORECASE)

# URL schemes before defanging (http/https/ftp)
_URL_RE = re.compile(r"https?://[^\s<>\"']+|ftp://[^\s<>\"']+", re.IGNORECASE)


def get_headers_txt(email: ParsedEmail) -> str:
    """Return the verbatim header block for writing to headers.txt.

    Returns email.headers_raw exactly as-is with no modification. If the
    raw header block is empty, returns a placeholder line instead.

    Args:
        email: Parsed email containing the raw header block.

    Returns:
        Verbatim headers string, or ``[No headers available]``.
    """
    try:
        if email.headers_raw:
            return email.headers_raw
        return "[No headers available]"
    except Exception:
        logger.exception("Failed to retrieve headers for headers.txt")
        return "[No headers available]"


def _parse_single_received(raw: str) -> dict[str, str]:
    """Parse one Received header value into a hop dict.

    Never raises — unparseable fields are left as empty strings.
    """
    hop = {
        "from_host": "",
        "from_ip": "",
        "by_host": "",
        "timestamp": "",
        "raw": raw,
    }

    try:
        from_match = _FROM_HOST_RE.search(raw)
        if from_match:
            hop["from_host"] = from_match.group(1).strip("<>")

        ip_match = _FROM_IP_BRACKET_RE.search(raw)
        if ip_match:
            hop["from_ip"] = ip_match.group(1)
        else:
            ipv4_match = _IPV4_RE.search(raw)
            if ipv4_match:
                hop["from_ip"] = ipv4_match.group(1)

        by_match = _BY_HOST_RE.search(raw)
        if by_match:
            # Strip trailing punctuation such as commas or semicolons
            hop["by_host"] = by_match.group(1).strip("<>").rstrip(".,;")

        if ";" in raw:
            hop["timestamp"] = raw.rsplit(";", 1)[-1].strip()
    except Exception:
        logger.exception("Failed to parse Received header: %s", raw[:120])

    return hop


def parse_hop_chain(email: ParsedEmail) -> list[dict]:
    """Parse Received: headers into a structured hop chain, oldest-first.

    Each hop dict contains: from_host, from_ip, by_host, timestamp, raw.
    All values are strings; missing fields are empty strings.

    Args:
        email: Parsed email with a headers dict containing Received values.

    Returns:
        List of hop dicts ordered from origin (first hop) to final delivery.
    """
    try:
        received_values = email.headers.get("received", [])
        if not received_values:
            return []

        # Received headers are reverse-chronological in the email; reverse for origin-first
        return [_parse_single_received(value) for value in reversed(received_values)]
    except Exception:
        logger.exception("Failed to parse hop chain from Received headers")
        return []


def _defang_url(url: str) -> str:
    """Defang a single URL match by replacing scheme and dots."""
    url = re.sub(r"https://", "hxxps://", url, flags=re.IGNORECASE)
    url = re.sub(r"http://", "hxxp://", url, flags=re.IGNORECASE)
    url = re.sub(r"ftp://", "fxxp://", url, flags=re.IGNORECASE)
    return url.replace(".", "[.]")


def _defang_ipv4(ip: str) -> str:
    """Defang a bare IPv4 address by replacing dots."""
    return ip.replace(".", "[.]")


def defang(text: str) -> str:
    """Defang URLs and IPv4 addresses in a string.

    Replaces URL schemes (http/https/ftp) and dots within matched URLs and
    bare IPv4 addresses. Plain English text and sentence-ending dots are
    left untouched.

    Args:
        text: Input string that may contain URLs, IPs, or arbitrary prose.

    Returns:
        Defanged copy of the input string.
    """
    try:
        if not text:
            return text

        url_matches = list(_URL_RE.finditer(text))
        replacements: list[tuple[int, int, str]] = []

        for match in url_matches:
            replacements.append((match.start(), match.end(), _defang_url(match.group())))

        url_spans = [(match.start(), match.end()) for match in url_matches]

        def _inside_url(position: int) -> bool:
            return any(start <= position < end for start, end in url_spans)

        for match in _IPV4_RE.finditer(text):
            if not _inside_url(match.start()):
                replacements.append(
                    (match.start(), match.end(), _defang_ipv4(match.group()))
                )

        # Apply replacements from end to start so indices remain valid
        replacements.sort(key=lambda item: item[0], reverse=True)
        result = text
        for start, end, replacement in replacements:
            result = result[:start] + replacement + result[end:]
        return result
    except Exception:
        logger.exception("Failed to defang text")
        return text
