"""Integration tests for HIVE using the simple_phishing.eml sample."""

from __future__ import annotations

from pathlib import Path

import pytest

from hive.batch import process_file
from hive.extractors.attachments import build_hashes_csv, collect_attachments
from hive.extractors.auth import auth_results_to_text, parse_auth_results
from hive.extractors.body import get_body_html_txt, get_body_txt
from hive.extractors.headers import defang, get_headers_txt, parse_hop_chain
from hive.extractors.urls import extract_urls
from hive.parser.common import sanitise_filename
from hive.parser.eml import parse_eml

SAMPLE_PATH = Path(__file__).parent / "samples" / "simple_phishing.eml"


@pytest.fixture(scope="module")
def parsed_email():
    """Parse the phishing sample once for reuse across tests."""
    return parse_eml(SAMPLE_PATH)


@pytest.fixture(scope="module")
def hops(parsed_email):
    """Parse the hop chain once for reuse across header tests."""
    return parse_hop_chain(parsed_email)


# ---------------------------------------------------------------------------
# GROUP 1: parser/eml.py
# ---------------------------------------------------------------------------


def test_eml_parses_without_error(parsed_email):
    assert parsed_email is not None


def test_eml_source_hash_populated(parsed_email):
    assert set(parsed_email.source_hash.keys()) == {"md5", "sha1", "sha256"}
    assert all(parsed_email.source_hash[key] for key in parsed_email.source_hash)


def test_eml_headers_raw_verbatim(parsed_email):
    assert parsed_email.headers_raw
    assert "Return-Path" in parsed_email.headers_raw
    assert "X-Originating-IP" in parsed_email.headers_raw


def test_eml_subject_decoded(parsed_email):
    assert parsed_email.subject == "URGENT: Invoice #4521 requires your attention"


def test_eml_sender(parsed_email):
    assert "supp1ier-portal.com" in parsed_email.sender


def test_eml_reply_to_present(parsed_email):
    assert parsed_email.reply_to is not None
    assert "gmail.com" in parsed_email.reply_to


def test_eml_recipients(parsed_email):
    assert isinstance(parsed_email.recipients, list)
    assert len(parsed_email.recipients) >= 1
    assert any("vunhst.nhs.uk" in recipient for recipient in parsed_email.recipients)


def test_eml_date_utc(parsed_email):
    assert "UTC" in parsed_email.date


def test_eml_body_plain_present(parsed_email):
    assert parsed_email.body_plain is not None
    assert "invoice" in parsed_email.body_plain.lower()


def test_eml_reply_to_mismatch_warning(parsed_email):
    assert "Reply-To does not match From domain" in parsed_email.warnings


def test_eml_no_attachments(parsed_email):
    assert parsed_email.attachments == []


def test_eml_no_nested_emails(parsed_email):
    assert parsed_email.nested_emails == []


# ---------------------------------------------------------------------------
# GROUP 2: extractors/headers.py
# ---------------------------------------------------------------------------


def test_headers_txt_verbatim(parsed_email):
    headers_txt = get_headers_txt(parsed_email)
    assert headers_txt.startswith("Return-Path")
    assert "X-Originating-IP: 185.220.101.45" in headers_txt


def test_hop_chain_length(hops):
    assert len(hops) == 2


def test_hop_chain_oldest_first(hops):
    assert "localhost" in hops[0]["from_host"]
    assert "supp1ier-portal" in hops[1]["from_host"]
    assert hops[1]["from_ip"] == "185.220.101.45"


def test_defang_http():
    assert defang("http://evil.com/path") == "hxxp://evil[.]com/path"


def test_defang_https():
    assert defang("https://evil.com") == "hxxps://evil[.]com"


def test_defang_ip():
    assert defang("185.220.101.45") == "185[.]220[.]101[.]45"


def test_defang_leaves_prose():
    result = defang("This is a sentence. With dots.")
    assert result == "This is a sentence. With dots."


# ---------------------------------------------------------------------------
# GROUP 3: extractors/auth.py
# ---------------------------------------------------------------------------


def test_spf_fail(parsed_email):
    assert parse_auth_results(parsed_email).spf.result == "fail"


def test_dmarc_fail(parsed_email):
    assert parse_auth_results(parsed_email).dmarc.result == "fail"


def test_dkim_none_or_unverified(parsed_email):
    result = parse_auth_results(parsed_email).dkim.result
    assert result in ("none", "present (unverified)")


def test_auth_results_to_text_contains_spf(parsed_email):
    text = auth_results_to_text(parse_auth_results(parsed_email))
    assert "SPF" in text
    assert "FAIL" in text


# ---------------------------------------------------------------------------
# GROUP 4: extractors/body.py
# ---------------------------------------------------------------------------


def test_body_txt_content(parsed_email):
    assert "invoice" in get_body_txt(parsed_email)


def test_body_html_txt_no_html(parsed_email):
    assert get_body_html_txt(parsed_email) == "[No HTML body available]"


# ---------------------------------------------------------------------------
# GROUP 5: extractors/urls.py
# ---------------------------------------------------------------------------


def test_url_count(parsed_email):
    assert len(extract_urls(parsed_email)) >= 2


def test_urls_defanged(parsed_email):
    for finding in extract_urls(parsed_email):
        assert "hxxp" in finding.defanged_url or "hxxps" in finding.defanged_url
        assert "[.]" in finding.defanged_url


def test_urls_source_label(parsed_email):
    sources = [finding.source for finding in extract_urls(parsed_email)]
    assert any("body" in source for source in sources)


def test_no_live_urls_in_output(parsed_email):
    for finding in extract_urls(parsed_email):
        assert not finding.defanged_url.startswith("http")


# ---------------------------------------------------------------------------
# GROUP 6: extractors/attachments.py
# ---------------------------------------------------------------------------


def test_collect_attachments_empty(parsed_email):
    assert collect_attachments(parsed_email) == []


def test_build_hashes_csv_header_only():
    csv_output = build_hashes_csv([])
    assert csv_output.startswith('"filename"')
    assert "sha256" in csv_output


# ---------------------------------------------------------------------------
# GROUP 7: sanitise_filename (parser/common.py)
# ---------------------------------------------------------------------------


def test_sanitise_path_traversal():
    assert sanitise_filename("../../etc/passwd") == "passwd"


def test_sanitise_unsafe_chars():
    result = sanitise_filename("evil:file?.exe")
    assert "/" not in result
    assert "?" not in result
    assert ":" not in result


def test_sanitise_empty():
    assert sanitise_filename("") == "unnamed_attachment"


def test_sanitise_leading_dot():
    result = sanitise_filename(".hidden_file")
    assert not result.startswith(".")


# ---------------------------------------------------------------------------
# GROUP 8: batch.py integration
# ---------------------------------------------------------------------------


def test_process_file_success(tmp_path):
    result = process_file(SAMPLE_PATH, tmp_path)
    assert result.success is True
    assert result.error == ""
    assert result.attachment_count == 0
    assert result.url_count >= 2


def test_process_file_wrong_extension(tmp_path):
    bad_file = tmp_path / "not_an_email.txt"
    bad_file.write_text("not an email", encoding="utf-8")
    result = process_file(bad_file, tmp_path / "output")
    assert result.success is False
    assert "extension" in result.error.lower()


def test_process_file_output_files_exist(tmp_path):
    result = process_file(SAMPLE_PATH, tmp_path)
    output_path = result.output_path
    assert output_path is not None
    assert (output_path / "headers.txt").exists()
    assert (output_path / "summary.txt").exists()
    assert (output_path / "urls.txt").exists()
    assert (output_path / "hashes.csv").exists()
    assert (output_path / "auth_analysis.txt").exists()
    assert (output_path / "body.txt").exists()
    assert (output_path / "body.html.txt").exists()


NESTED_SAMPLE_PATH = Path(__file__).parent / "samples" / "nested_email.eml"


@pytest.fixture(scope="module")
def nested_email():
    """Parse the nested email sample once for reuse across tests."""
    return parse_eml(NESTED_SAMPLE_PATH)


# ---------------------------------------------------------------------------
# GROUP 9: Outer email parsing
# ---------------------------------------------------------------------------


def test_nested_eml_parses_without_error(nested_email):
    assert nested_email is not None


def test_nested_eml_subject(nested_email):
    assert nested_email.subject == "FWD: Urgent password reset required"


def test_nested_eml_sender_domain(nested_email):
    assert "forward-srv.net" in nested_email.sender


def test_nested_eml_reply_to_mismatch(nested_email):
    assert "Reply-To does not match From domain" in nested_email.warnings


def test_nested_eml_body_plain_present(nested_email):
    assert nested_email.body_plain is not None
    assert "forwarded" in nested_email.body_plain.lower()


def test_nested_eml_hop_chain(nested_email):
    hops = parse_hop_chain(nested_email)
    assert len(hops) == 2
    assert hops[0]["from_ip"] == "127.0.0.1"
    assert hops[1]["from_ip"] == "91.108.4.200"


def test_nested_eml_spf_softfail(nested_email):
    assert parse_auth_results(nested_email).spf.result == "softfail"


def test_nested_eml_dmarc_fail(nested_email):
    assert parse_auth_results(nested_email).dmarc.result == "fail"


# ---------------------------------------------------------------------------
# GROUP 10: Nested email structure
# ---------------------------------------------------------------------------


def test_nested_email_found(nested_email):
    assert len(nested_email.nested_emails) == 1


def test_nested_email_depth(nested_email):
    assert nested_email.nested_emails[0].depth == 1


def test_nested_email_no_attachments_on_outer(nested_email):
    assert nested_email.attachments == []


# ---------------------------------------------------------------------------
# GROUP 11: Inner email content
# ---------------------------------------------------------------------------


def test_inner_email_subject(nested_email):
    inner = nested_email.nested_emails[0]
    assert "suspended" in inner.subject.lower()


def test_inner_email_sender_domain(nested_email):
    inner = nested_email.nested_emails[0]
    assert "secure-login-portal.net" in inner.sender


def test_inner_email_spf_fail(nested_email):
    inner = nested_email.nested_emails[0]
    assert parse_auth_results(inner).spf.result == "fail"


def test_inner_email_dmarc_fail(nested_email):
    inner = nested_email.nested_emails[0]
    assert parse_auth_results(inner).dmarc.result == "fail"


def test_inner_email_body_contains_url(nested_email):
    inner = nested_email.nested_emails[0]
    assert inner.body_plain is not None
    assert "secure-login-portal.net" in inner.body_plain


# ---------------------------------------------------------------------------
# GROUP 12: URL extraction across nesting levels
# ---------------------------------------------------------------------------


def test_nested_url_extraction_finds_inner_urls(nested_email):
    findings = extract_urls(nested_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("secure-login-portal" in url for url in all_urls)


def test_nested_url_source_labels(nested_email):
    findings = extract_urls(nested_email)
    sources = [finding.source for finding in findings]
    assert any("nested" in source for source in sources)


def test_nested_urls_all_defanged(nested_email):
    findings = extract_urls(nested_email)
    for finding in findings:
        assert not finding.defanged_url.startswith("http")
        assert "[.]" in finding.defanged_url


def test_nested_url_depth_label(nested_email):
    findings = extract_urls(nested_email)
    nested_findings = [finding for finding in findings if "nested[1]" in finding.source]
    assert len(nested_findings) >= 2


# ---------------------------------------------------------------------------
# GROUP 13: Batch processing with nested email
# ---------------------------------------------------------------------------


def test_process_file_nested_success(tmp_path):
    result = process_file(NESTED_SAMPLE_PATH, tmp_path)
    assert result.success is True
    assert result.url_count >= 2


def test_process_file_nested_output_structure(tmp_path):
    result = process_file(NESTED_SAMPLE_PATH, tmp_path)
    out = result.output_path
    assert (out / "headers.txt").exists()
    assert (out / "summary.txt").exists()
    assert (out / "urls.txt").exists()
    assert (out / "auth_analysis.txt").exists()
    assert (out / "body.txt").exists()
    assert (out / "body.html.txt").exists()
    nested_dirs = [
        path for path in out.iterdir() if path.is_dir() and path.name.startswith("nested_")
    ]
    assert len(nested_dirs) == 1


def test_process_file_nested_inner_files(tmp_path):
    result = process_file(NESTED_SAMPLE_PATH, tmp_path)
    out = result.output_path
    nested_dirs = [
        path for path in out.iterdir() if path.is_dir() and path.name.startswith("nested_")
    ]
    inner = nested_dirs[0]
    assert (inner / "headers.txt").exists()
    assert (inner / "summary.txt").exists()
    assert (inner / "urls.txt").exists()
    assert (inner / "auth_analysis.txt").exists()


def test_nested_headers_txt_verbatim(tmp_path):
    result = process_file(NESTED_SAMPLE_PATH, tmp_path)
    out = result.output_path
    outer_headers = (out / "headers.txt").read_text(encoding="utf-8")
    assert "Return-Path" in outer_headers
    assert "X-Originating-IP" in outer_headers
    nested_dirs = [
        path for path in out.iterdir() if path.is_dir() and path.name.startswith("nested_")
    ]
    inner_headers = (nested_dirs[0] / "headers.txt").read_text(encoding="utf-8")
    assert "secure-login-portal.net" in inner_headers


def test_nested_urls_txt_contains_inner_urls(tmp_path):
    result = process_file(NESTED_SAMPLE_PATH, tmp_path)
    out = result.output_path
    nested_dirs = [
        path for path in out.iterdir() if path.is_dir() and path.name.startswith("nested_")
    ]
    inner_urls = (nested_dirs[0] / "urls.txt").read_text(encoding="utf-8")
    assert "secure-login-portal" in inner_urls
    assert "hxxp" in inner_urls or "hxxps" in inner_urls
