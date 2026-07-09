"""SPF, DKIM, DMARC, and ARC authentication header analysis for HIVE.

Parses stamped authentication results from receiving mail servers. Reads
only headers already present on the ParsedEmail — no DNS lookups or
network calls are made.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from hive.parser.common import ParsedEmail

logger = logging.getLogger(__name__)

# Received-SPF: leading result word (pass, fail, softfail, etc.)
_RECEIVED_SPF_RESULT_RE = re.compile(
    r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)

# Parenthetical detail block in Received-SPF values
_RECEIVED_SPF_PARENS_RE = re.compile(r"\(([^)]*)\)", re.DOTALL)

# Authentication-Results: spf=<result>
_AUTH_SPF_RE = re.compile(
    r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)",
    re.IGNORECASE,
)

# Authentication-Results: smtp.mailfrom= and smtp.helo= detail clauses
_AUTH_SPF_MAILFROM_RE = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
_AUTH_SPF_HELO_RE = re.compile(r"smtp\.helo=([^\s;]+)", re.IGNORECASE)

# Authentication-Results: dkim=<result>
_AUTH_DKIM_RE = re.compile(
    r"dkim=(pass|fail|none|neutral|temperror|permerror)",
    re.IGNORECASE,
)

# DKIM-Signature tag: d= (signing domain)
_DKIM_D_RE = re.compile(r"\bd=([^;\s]+)", re.IGNORECASE)

# DKIM-Signature tag: s= (selector)
_DKIM_S_RE = re.compile(r"\bs=([^;\s]+)", re.IGNORECASE)

# Authentication-Results: header.d= and header.i= detail clauses
_AUTH_DKIM_HEADER_D_RE = re.compile(r"header\.d=([^\s;]+)", re.IGNORECASE)
_AUTH_DKIM_HEADER_I_RE = re.compile(r"header\.i=([^\s;]+)", re.IGNORECASE)

# Authentication-Results: dmarc=<result>
_AUTH_DMARC_RE = re.compile(
    r"dmarc=(pass|fail|bestguesspass|none|temperror|permerror)",
    re.IGNORECASE,
)

# Authentication-Results: header.from= and action= detail clauses
_AUTH_DMARC_FROM_RE = re.compile(r"header\.from=([^\s;]+)", re.IGNORECASE)
_AUTH_DMARC_ACTION_RE = re.compile(r"action=([^\s;]+)", re.IGNORECASE)

# ARC-Authentication-Results: arc=<result>
_AUTH_ARC_RE = re.compile(
    r"arc=(pass|fail|none|neutral|temperror|permerror)",
    re.IGNORECASE,
)

_SPF_RESULTS = frozenset(
    {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
)
_DKIM_RESULTS = frozenset(
    {"pass", "fail", "none", "neutral", "temperror", "permerror"}
)
_DMARC_RESULTS = frozenset(
    {"pass", "fail", "bestguesspass", "none", "temperror", "permerror"}
)
_ARC_RESULTS = frozenset(
    {"pass", "fail", "none", "neutral", "temperror", "permerror"}
)


@dataclass
class AuthResult:
    """Authentication outcome for a single protocol."""

    result: str  # normalised result token, e.g. pass, fail, none, present (unverified)
    raw: str  # full raw header value the result was parsed from
    details: str  # extra context such as domain, selector, or reason text


@dataclass
class AuthResults:
    """Combined SPF, DKIM, DMARC, and ARC authentication results."""

    spf: AuthResult
    dkim: AuthResult
    dmarc: AuthResult
    arc: AuthResult


def _default_auth_result() -> AuthResult:
    """Return the default empty authentication result."""
    return AuthResult(result="none", raw="", details="")


def _get_header_values(email: ParsedEmail, header_name: str) -> list[str]:
    """Return all values for a lowercase header name from the parsed email."""
    return email.headers.get(header_name.lower(), [])


def _join_details(parts: list[str]) -> str:
    """Join non-empty detail fragments with semicolons."""
    return "; ".join(part for part in parts if part)


def _parse_spf_details_from_auth(raw: str) -> str:
    """Extract SPF detail clauses from an Authentication-Results value."""
    details: list[str] = []
    mailfrom = _AUTH_SPF_MAILFROM_RE.search(raw)
    if mailfrom:
        details.append(f"smtp.mailfrom={mailfrom.group(1)}")
    helo = _AUTH_SPF_HELO_RE.search(raw)
    if helo:
        details.append(f"smtp.helo={helo.group(1)}")
    return _join_details(details)


def _parse_spf(email: ParsedEmail) -> AuthResult:
    """Parse SPF results from Received-SPF and Authentication-Results headers."""
    try:
        received_spf_values = _get_header_values(email, "received-spf")
        for raw in received_spf_values:
            match = _RECEIVED_SPF_RESULT_RE.match(raw)
            if match:
                result = match.group(1).lower()
                if result in _SPF_RESULTS:
                    parens = _RECEIVED_SPF_PARENS_RE.search(raw)
                    details = parens.group(1).strip() if parens else ""
                    return AuthResult(result=result, raw=raw, details=details)

        auth_values = _get_header_values(email, "authentication-results")
        for raw in auth_values:
            match = _AUTH_SPF_RE.search(raw)
            if match:
                result = match.group(1).lower()
                if result in _SPF_RESULTS:
                    return AuthResult(
                        result=result,
                        raw=raw,
                        details=_parse_spf_details_from_auth(raw),
                    )
    except Exception:
        logger.exception("Failed to parse SPF authentication results")

    return _default_auth_result()


def _parse_dkim_details_from_auth(raw: str) -> str:
    """Extract DKIM detail clauses from an Authentication-Results value."""
    details: list[str] = []
    header_d = _AUTH_DKIM_HEADER_D_RE.search(raw)
    if header_d:
        details.append(f"header.d={header_d.group(1)}")
    header_i = _AUTH_DKIM_HEADER_I_RE.search(raw)
    if header_i:
        details.append(f"header.i={header_i.group(1)}")
    return _join_details(details)


def _parse_dkim_signature_details(email: ParsedEmail) -> tuple[str, str]:
    """Return (result, details) when only DKIM-Signature is present."""
    signature_values = _get_header_values(email, "dkim-signature")
    if not signature_values:
        return "none", ""

    raw = signature_values[0]
    details: list[str] = []
    domain = _DKIM_D_RE.search(raw)
    if domain:
        details.append(f"d={domain.group(1)}")
    selector = _DKIM_S_RE.search(raw)
    if selector:
        details.append(f"s={selector.group(1)}")
    return "present (unverified)", _join_details(details)


def _parse_dkim(email: ParsedEmail) -> AuthResult:
    """Parse DKIM results from Authentication-Results and DKIM-Signature headers."""
    try:
        auth_values = _get_header_values(email, "authentication-results")
        for raw in auth_values:
            match = _AUTH_DKIM_RE.search(raw)
            if match:
                result = match.group(1).lower()
                if result in _DKIM_RESULTS and result != "none":
                    return AuthResult(
                        result=result,
                        raw=raw,
                        details=_parse_dkim_details_from_auth(raw),
                    )

        # Fall back to DKIM-Signature presence when no verified result was stamped
        dkim_result, details = _parse_dkim_signature_details(email)
        if dkim_result != "none":
            raw_values = _get_header_values(email, "dkim-signature")
            return AuthResult(
                result=dkim_result,
                raw=raw_values[0] if raw_values else "",
                details=details,
            )

        # Authentication-Results may explicitly record dkim=none
        for raw in auth_values:
            match = _AUTH_DKIM_RE.search(raw)
            if match:
                result = match.group(1).lower()
                if result in _DKIM_RESULTS:
                    return AuthResult(
                        result=result,
                        raw=raw,
                        details=_parse_dkim_details_from_auth(raw),
                    )
    except Exception:
        logger.exception("Failed to parse DKIM authentication results")

    return _default_auth_result()


def _parse_dmarc_details(raw: str) -> str:
    """Extract DMARC detail clauses from an Authentication-Results value."""
    details: list[str] = []
    header_from = _AUTH_DMARC_FROM_RE.search(raw)
    if header_from:
        details.append(f"header.from={header_from.group(1)}")
    action = _AUTH_DMARC_ACTION_RE.search(raw)
    if action:
        details.append(f"action={action.group(1)}")
    return _join_details(details)


def _parse_dmarc(email: ParsedEmail) -> AuthResult:
    """Parse DMARC results from Authentication-Results headers."""
    try:
        auth_values = _get_header_values(email, "authentication-results")
        for raw in auth_values:
            match = _AUTH_DMARC_RE.search(raw)
            if match:
                result = match.group(1).lower()
                if result in _DMARC_RESULTS:
                    return AuthResult(
                        result=result,
                        raw=raw,
                        details=_parse_dmarc_details(raw),
                    )
    except Exception:
        logger.exception("Failed to parse DMARC authentication results")

    return _default_auth_result()


def _parse_arc(email: ParsedEmail) -> AuthResult:
    """Parse ARC results from ARC-Authentication-Results headers."""
    try:
        arc_values = _get_header_values(email, "arc-authentication-results")
        if not arc_values:
            return _default_auth_result()

        raw = arc_values[0]
        details = raw[:500] + (" [truncated]" if len(raw) > 500 else "")

        for value in arc_values:
            match = _AUTH_ARC_RE.search(value)
            if match:
                result = match.group(1).lower()
                if result in _ARC_RESULTS:
                    return AuthResult(result=result, raw=value, details=details)

        return AuthResult(result="present", raw=raw, details=details)
    except Exception:
        logger.exception("Failed to parse ARC authentication results")

    return _default_auth_result()


def parse_auth_results(email: ParsedEmail) -> AuthResults:
    """Parse SPF, DKIM, DMARC, and ARC authentication results from headers.

    Reads stamped receiving-server results only. No DNS or network activity
    is performed.

    Args:
        email: Parsed email with a headers dict.

    Returns:
        AuthResults containing one AuthResult per protocol.
    """
    try:
        return AuthResults(
            spf=_parse_spf(email),
            dkim=_parse_dkim(email),
            dmarc=_parse_dmarc(email),
            arc=_parse_arc(email),
        )
    except Exception:
        logger.exception("Failed to parse authentication results")
        default = _default_auth_result()
        return AuthResults(spf=default, dkim=default, dmarc=default, arc=default)


def _format_output_field(value: str) -> str:
    """Format a details or raw field for auth_analysis.txt output."""
    return value if value else "N/A"


def _format_output_raw(raw: str) -> str:
    """Format a raw header value, truncating long values for readability."""
    if not raw:
        return "N/A"
    if len(raw) > 200:
        return raw[:200] + " [truncated]"
    return raw


def _format_protocol_block(name: str, result: AuthResult) -> str:
    """Format one protocol section for auth_analysis.txt."""
    return (
        f"{name}\n"
        f"  Result  : {result.result.upper()}\n"
        f"  Details : {_format_output_field(result.details)}\n"
        f"  Raw     : {_format_output_raw(result.raw)}"
    )


def auth_results_to_text(results: AuthResults) -> str:
    """Return the full auth_analysis.txt content for the given results.

    Args:
        results: Parsed authentication results for one email.

    Returns:
        Formatted multi-protocol authentication analysis text.
    """
    try:
        blocks = [
            "# HIVE Authentication Analysis",
            "# ─────────────────────────────────────────────",
            "",
            _format_protocol_block("SPF", results.spf),
            "",
            _format_protocol_block("DKIM", results.dkim),
            "",
            _format_protocol_block("DMARC", results.dmarc),
            "",
            _format_protocol_block("ARC", results.arc),
            "",
        ]
        return "\n".join(blocks)
    except Exception:
        logger.exception("Failed to format authentication results as text")
        return "# HIVE Authentication Analysis\n# ─────────────────────────────────────────────\n"
