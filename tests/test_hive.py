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


import shutil

from hive.batch import process_directory

ATTACH_SAMPLE_PATH = Path(__file__).parent / "samples" / "with_attachment.eml"
MALFORMED_PATH = Path(__file__).parent / "samples" / "malformed_headers.eml"
HTML_ONLY_PATH = Path(__file__).parent / "samples" / "html_only.eml"
PDF_SAMPLE_PATH = Path(__file__).parent / "samples" / "pdf_attachment.eml"
DOCX_SAMPLE_PATH = Path(__file__).parent / "samples" / "docx_attachment.eml"
XLSX_SAMPLE_PATH = Path(__file__).parent / "samples" / "xlsx_attachment.eml"
PPTX_SAMPLE_PATH = Path(__file__).parent / "samples" / "pptx_attachment.eml"
RTF_SAMPLE_PATH = Path(__file__).parent / "samples" / "rtf_attachment.eml"


@pytest.fixture(scope="module")
def attach_email():
    """Parse the attachment sample once for reuse across tests."""
    return parse_eml(ATTACH_SAMPLE_PATH)


@pytest.fixture(scope="module")
def malformed_email():
    """Parse the malformed headers sample once for reuse across tests."""
    return parse_eml(MALFORMED_PATH)


@pytest.fixture(scope="module")
def html_only_email():
    """Parse the HTML-only sample once for reuse across tests."""
    return parse_eml(HTML_ONLY_PATH)


@pytest.fixture(scope="module")
def pdf_email():
    """Parse the PDF attachment sample once for reuse across tests."""
    return parse_eml(PDF_SAMPLE_PATH)


@pytest.fixture(scope="module")
def docx_email():
    """Parse the DOCX attachment sample once for reuse across tests."""
    return parse_eml(DOCX_SAMPLE_PATH)


@pytest.fixture(scope="module")
def xlsx_email():
    """Parse the XLSX attachment sample once for reuse across tests."""
    return parse_eml(XLSX_SAMPLE_PATH)


@pytest.fixture(scope="module")
def pptx_email():
    """Parse the PPTX attachment sample once for reuse across tests."""
    return parse_eml(PPTX_SAMPLE_PATH)


@pytest.fixture(scope="module")
def rtf_email():
    """Parse the RTF attachment sample once for reuse across tests."""
    return parse_eml(RTF_SAMPLE_PATH)


# ---------------------------------------------------------------------------
# GROUP 14: with_attachment.eml — attachment pipeline
# ---------------------------------------------------------------------------


def test_attach_email_parses(attach_email):
    assert attach_email is not None
    assert attach_email.subject == "Q1 2024 Budget Summary - Action Required"


def test_attach_email_has_one_attachment(attach_email):
    assert len(attach_email.attachments) == 1


def test_attach_filename_sanitised(attach_email):
    attachment = attach_email.attachments[0]
    assert attachment.filename == "budget_summary.txt"
    assert attachment.original_filename == "budget_summary.txt"


def test_attach_hashes_populated(attach_email):
    attachment = attach_email.attachments[0]
    assert attachment.hashes["md5"]
    assert attachment.hashes["sha1"]
    assert attachment.hashes["sha256"]
    assert len(attachment.hashes["sha256"]) == 64


def test_attach_size_nonzero(attach_email):
    attachment = attach_email.attachments[0]
    assert attachment.size > 0


def test_attach_content_type(attach_email):
    attachment = attach_email.attachments[0]
    assert "text" in attachment.content_type.lower()


def test_attach_has_macros_none_for_txt(attach_email):
    attachment = attach_email.attachments[0]
    assert attachment.has_macros is None


def test_attach_body_urls_found(attach_email):
    findings = extract_urls(attach_email)
    body_findings = [finding for finding in findings if finding.source == "body:plain"]
    assert len(body_findings) >= 2


def test_attach_attachment_urls_found(attach_email):
    findings = extract_urls(attach_email)
    attachment_findings = [
        finding for finding in findings if finding.source == "attachment:budget_summary.txt"
    ]
    assert len(attachment_findings) >= 2


def test_attach_all_urls_defanged(attach_email):
    for finding in extract_urls(attach_email):
        assert not finding.defanged_url.startswith("http")
        assert "[.]" in finding.defanged_url


def test_attach_hashes_csv_has_row(attach_email):
    attachments = collect_attachments(attach_email)
    csv_output = build_hashes_csv(attachments)
    lines = csv_output.strip().split("\n")
    assert len(lines) == 2
    assert "budget_summary.txt" in csv_output


def test_attach_collect_attachments_count(attach_email):
    attachments = collect_attachments(attach_email)
    assert len(attachments) == 1


def test_attach_spf_fail(attach_email):
    assert parse_auth_results(attach_email).spf.result == "fail"


def test_attach_no_reply_to_mismatch(attach_email):
    assert "Reply-To does not match From domain" not in attach_email.warnings


def test_attach_process_file_output(tmp_path):
    result = process_file(ATTACH_SAMPLE_PATH, tmp_path)
    assert result.success is True
    assert result.attachment_count == 1
    assert result.url_count >= 4
    output_path = result.output_path
    assert (output_path / "hashes.csv").exists()
    assert (output_path / "attachments" / "budget_summary.txt").exists()


def test_attach_no_extract_flag(tmp_path):
    result = process_file(ATTACH_SAMPLE_PATH, tmp_path, no_extract=True)
    assert result.success is True
    assert not (result.output_path / "attachments").exists()
    assert (result.output_path / "hashes.csv").exists()


# ---------------------------------------------------------------------------
# GROUP 15: malformed_headers.eml — resilience
# ---------------------------------------------------------------------------


def test_malformed_parses_without_crash(malformed_email):
    assert malformed_email is not None


def test_malformed_subject_present(malformed_email):
    assert malformed_email.subject == "You have a new message"


def test_malformed_sender_present(malformed_email):
    assert "suspicious.org" in malformed_email.sender


def test_malformed_date_empty_or_string(malformed_email):
    assert isinstance(malformed_email.date, str)


def test_malformed_no_received_headers(malformed_email):
    hops = parse_hop_chain(malformed_email)
    assert hops == []


def test_malformed_auth_results_default(malformed_email):
    results = parse_auth_results(malformed_email)
    assert results.spf.result == "none"
    assert results.dkim.result == "none"
    assert results.dmarc.result == "none"
    assert results.arc.result == "none"


def test_malformed_body_still_extracted(malformed_email):
    assert malformed_email.body_plain is not None
    assert "suspicious.org" in malformed_email.body_plain


def test_malformed_url_still_found(malformed_email):
    findings = extract_urls(malformed_email)
    assert len(findings) >= 1
    assert any("suspicious" in finding.defanged_url for finding in findings)


def test_malformed_headers_raw_nonempty(malformed_email):
    assert malformed_email.headers_raw
    assert "From" in malformed_email.headers_raw


def test_malformed_source_hash_populated(malformed_email):
    assert malformed_email.source_hash["sha256"]


def test_malformed_process_file_succeeds(tmp_path):
    result = process_file(MALFORMED_PATH, tmp_path)
    assert result.success is True
    output_path = result.output_path
    assert (output_path / "headers.txt").exists()
    assert (output_path / "summary.txt").exists()


# ---------------------------------------------------------------------------
# GROUP 16: html_only.eml — HTML body handling
# ---------------------------------------------------------------------------


def test_html_only_parses(html_only_email):
    assert html_only_email is not None


def test_html_only_body_plain_is_none(html_only_email):
    assert html_only_email.body_plain is None


def test_html_only_body_html_present(html_only_email):
    assert html_only_email.body_html is not None
    assert "<html>" in html_only_email.body_html.lower()


def test_html_only_body_txt_fallback(html_only_email):
    result = get_body_txt(html_only_email)
    assert "[Plain text body not available — extracted from HTML]" in result
    assert "verify" in result.lower()


def test_html_only_body_txt_no_script_content(html_only_email):
    result = get_body_txt(html_only_email)
    assert "window.onload" not in result
    assert "<script>" not in result


def test_html_only_body_txt_no_style_content(html_only_email):
    result = get_body_txt(html_only_email)
    assert "font-family" not in result
    assert "<style>" not in result


def test_html_only_body_html_txt_has_safety_header(html_only_email):
    result = get_body_html_txt(html_only_email)
    assert "DO NOT OPEN THIS FILE IN A BROWSER" in result
    assert "DO NOT CLICK ANY LINKS" in result


def test_html_only_body_html_txt_contains_raw_html(html_only_email):
    result = get_body_html_txt(html_only_email)
    assert "<html>" in result.lower()
    assert "window.onload" in result


def test_html_only_urls_from_href(html_only_email):
    findings = extract_urls(html_only_email)
    defanged_urls = [finding.defanged_url for finding in findings]
    assert any("html-mailer" in url for url in defanged_urls)


def test_html_only_urls_defanged(html_only_email):
    for finding in extract_urls(html_only_email):
        assert not finding.defanged_url.startswith("http")


def test_html_only_spf_pass(html_only_email):
    assert parse_auth_results(html_only_email).spf.result == "pass"


def test_html_only_dkim_pass(html_only_email):
    assert parse_auth_results(html_only_email).dkim.result == "pass"


def test_html_only_dmarc_pass(html_only_email):
    assert parse_auth_results(html_only_email).dmarc.result == "pass"


# ---------------------------------------------------------------------------
# GROUP 17: defang edge cases
# ---------------------------------------------------------------------------


def test_defang_empty_string():
    assert defang("") == ""


def test_defang_already_defanged():
    assert defang("hxxp://evil[.]com") == "hxxp://evil[.]com"


def test_defang_ftp():
    assert defang("ftp://files.evil.com/payload") == "fxxp://files[.]evil[.]com/payload"


def test_defang_multiple_urls_in_one_string():
    text = "See http://evil.com and also https://bad.net/path"
    result = defang(text)
    assert "hxxp://evil[.]com" in result
    assert "hxxps://bad[.]net/path" in result


def test_defang_url_with_port():
    result = defang("http://evil.com:8080/path")
    assert result.startswith("hxxp://")
    assert "[.]" in result


def test_defang_ip_in_url():
    result = defang("http://192.168.1.1/admin")
    assert result.startswith("hxxp://")
    assert "192" in result


def test_defang_bare_ip_not_in_url():
    result = defang("Sender IP: 10.0.0.1")
    assert "10[.]0[.]0[.]1" in result


def test_defang_no_false_positive_version_numbers():
    result = defang("Python 3.10.4 is installed")
    assert result == "Python 3.10.4 is installed"


# ---------------------------------------------------------------------------
# GROUP 18: sanitise_filename edge cases
# ---------------------------------------------------------------------------


def test_sanitise_windows_reserved_name():
    result = sanitise_filename("CON.txt")
    assert result is not None
    assert len(result) > 0


def test_sanitise_very_long_filename():
    long_name = "a" * 300 + ".exe"
    result = sanitise_filename(long_name)
    assert len(result) <= 200


def test_sanitise_unicode_filename():
    result = sanitise_filename("ñoño_attachment.pdf")
    assert result is not None
    assert len(result) > 0


def test_sanitise_only_dots():
    result = sanitise_filename("...")
    assert result == "unnamed_attachment"


def test_sanitise_only_unsafe_chars():
    result = sanitise_filename("***???<<<")
    assert result == "unnamed_attachment" or len(result) > 0


def test_sanitise_mixed_separators():
    result = sanitise_filename("..\\..\\windows\\system32\\evil.exe")
    assert "windows" not in result.lower()
    assert "system32" not in result.lower()
    assert result.endswith(".exe") or result == "evil.exe"


def test_sanitise_null_bytes():
    result = sanitise_filename("evil\x00file.exe")
    assert "\x00" not in result


# ---------------------------------------------------------------------------
# GROUP 19: process_directory
# ---------------------------------------------------------------------------


def test_process_directory_with_multiple_files(tmp_path):
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(SAMPLE_PATH, samples_dir / SAMPLE_PATH.name)
    shutil.copy(MALFORMED_PATH, samples_dir / MALFORMED_PATH.name)
    results = process_directory(samples_dir, tmp_path / "output")
    assert len(results) == 2
    assert all(result.success for result in results)


def test_process_directory_empty(tmp_path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    results = process_directory(empty_dir, tmp_path / "output")
    assert results == []


def test_process_directory_ignores_non_email_files(tmp_path):
    mixed_dir = tmp_path / "mixed"
    mixed_dir.mkdir()
    shutil.copy(SAMPLE_PATH, mixed_dir / SAMPLE_PATH.name)
    (mixed_dir / "readme.txt").write_text("not an email", encoding="utf-8")
    (mixed_dir / "image.png").write_bytes(b"\x89PNG\r\n")
    results = process_directory(mixed_dir, tmp_path / "output")
    assert len(results) == 1
    assert results[0].success is True


def test_process_directory_invalid_path(tmp_path):
    results = process_directory(tmp_path / "nonexistent", tmp_path / "output")
    assert len(results) == 1
    assert results[0].success is False


# ---------------------------------------------------------------------------
# GROUP 20: output collision handling
# ---------------------------------------------------------------------------


def test_output_dir_collision(tmp_path):
    result1 = process_file(SAMPLE_PATH, tmp_path)
    result2 = process_file(SAMPLE_PATH, tmp_path)
    assert result1.output_path is not None
    assert result2.output_path is not None
    assert result1.output_path.is_dir()
    assert result1.output_path != result2.output_path
    assert result1.output_path.exists()
    assert result2.output_path.exists()
    assert result2.output_path.name.endswith("_1")


# ---------------------------------------------------------------------------
# GROUP 21: evidence integrity
# ---------------------------------------------------------------------------


def test_source_hash_is_deterministic():
    email1 = parse_eml(SAMPLE_PATH)
    email2 = parse_eml(SAMPLE_PATH)
    assert email1.source_hash == email2.source_hash


def test_source_hash_differs_for_different_files():
    email1 = parse_eml(SAMPLE_PATH)
    email2 = parse_eml(MALFORMED_PATH)
    assert email1.source_hash["sha256"] != email2.source_hash["sha256"]


def test_source_hash_in_summary_txt(tmp_path):
    result = process_file(SAMPLE_PATH, tmp_path)
    summary = (result.output_path / "summary.txt").read_text(encoding="utf-8")
    email = parse_eml(SAMPLE_PATH)
    assert email.source_hash["sha256"] in summary
    assert email.source_hash["md5"] in summary


# ---------------------------------------------------------------------------
# GROUP 22: hive.log
# ---------------------------------------------------------------------------


def test_hive_log_created(tmp_path):
    result = process_file(SAMPLE_PATH, tmp_path)
    assert (result.output_path / "hive.log").exists()


def test_hive_log_not_empty(tmp_path):
    result = process_file(SAMPLE_PATH, tmp_path)
    log_content = (result.output_path / "hive.log").read_text(encoding="utf-8")
    assert len(log_content) > 0


def test_hive_log_contains_utc(tmp_path):
    result = process_file(SAMPLE_PATH, tmp_path)
    log_content = (result.output_path / "hive.log").read_text(encoding="utf-8")
    assert "UTC" in log_content


# ---------------------------------------------------------------------------
# GROUP 23: auth_results_to_text formatting
# ---------------------------------------------------------------------------


def test_auth_text_all_four_protocols_present():
    results = parse_auth_results(parse_eml(SAMPLE_PATH))
    text = auth_results_to_text(results)
    assert "SPF" in text
    assert "DKIM" in text
    assert "DMARC" in text
    assert "ARC" in text


def test_auth_text_results_uppercase():
    results = parse_auth_results(parse_eml(SAMPLE_PATH))
    text = auth_results_to_text(results)
    assert "FAIL" in text
    assert "NONE" in text


def test_auth_text_pass_for_html_only():
    results = parse_auth_results(parse_eml(HTML_ONLY_PATH))
    text = auth_results_to_text(results)
    assert "PASS" in text


# ---------------------------------------------------------------------------
# GROUP 24: pdf_attachment.eml — PDF URL extraction
# ---------------------------------------------------------------------------


def test_pdf_email_parses(pdf_email):
    assert pdf_email is not None
    assert pdf_email.subject == "Q1 Financial Report - Review Required"


def test_pdf_email_has_one_attachment(pdf_email):
    assert len(pdf_email.attachments) == 1


def test_pdf_attachment_filename(pdf_email):
    assert pdf_email.attachments[0].filename == "report.pdf"


def test_pdf_attachment_content_type(pdf_email):
    assert "pdf" in pdf_email.attachments[0].content_type.lower()


def test_pdf_attachment_hashes_populated(pdf_email):
    attachment = pdf_email.attachments[0]
    assert attachment.hashes["md5"]
    assert attachment.hashes["sha256"]
    assert len(attachment.hashes["sha256"]) == 64


def test_pdf_attachment_size_nonzero(pdf_email):
    assert pdf_email.attachments[0].size > 0


def test_pdf_body_url_found(pdf_email):
    findings = extract_urls(pdf_email)
    body_findings = [finding for finding in findings if finding.source == "body:plain"]
    assert len(body_findings) >= 1
    assert any("quarterly-docs" in finding.defanged_url for finding in body_findings)


def test_pdf_attachment_urls_found(pdf_email):
    findings = extract_urls(pdf_email)
    pdf_findings = [finding for finding in findings if finding.source == "attachment:report.pdf"]
    assert len(pdf_findings) >= 2


def test_pdf_attachment_urls_defanged(pdf_email):
    findings = extract_urls(pdf_email)
    pdf_findings = [finding for finding in findings if finding.source == "attachment:report.pdf"]
    for finding in pdf_findings:
        assert not finding.defanged_url.startswith("http")
        assert "[.]" in finding.defanged_url


def test_pdf_malicious_url_found(pdf_email):
    findings = extract_urls(pdf_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("malicious-pdf-link" in url for url in all_urls)


def test_pdf_support_url_found(pdf_email):
    findings = extract_urls(pdf_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("pdf-support" in url for url in all_urls)


def test_pdf_total_url_count(pdf_email):
    findings = extract_urls(pdf_email)
    assert len(findings) == 3


def test_pdf_spf_fail(pdf_email):
    assert parse_auth_results(pdf_email).spf.result == "fail"


def test_pdf_process_file_output(tmp_path):
    result = process_file(PDF_SAMPLE_PATH, tmp_path)
    assert result.success is True
    assert result.attachment_count == 1
    assert result.url_count == 3
    output_path = result.output_path
    assert (output_path / "attachments" / "report.pdf").exists()
    assert (output_path / "hashes.csv").exists()
    csv_content = (output_path / "hashes.csv").read_text(encoding="utf-8")
    assert "report.pdf" in csv_content
    urls_content = (output_path / "urls.txt").read_text(encoding="utf-8")
    assert "malicious-pdf-link" in urls_content
    assert "attachment:report.pdf" in urls_content


# ---------------------------------------------------------------------------
# GROUP 25: docx_attachment.eml — DOCX URL extraction
# ---------------------------------------------------------------------------


def test_docx_email_parses(docx_email):
    assert docx_email is not None
    assert docx_email.subject == "Q1 Word Report - Review Required"


def test_docx_has_one_attachment(docx_email):
    assert len(docx_email.attachments) == 1


def test_docx_attachment_filename(docx_email):
    assert docx_email.attachments[0].filename == "report.docx"


def test_docx_attachment_hashes_populated(docx_email):
    attachment = docx_email.attachments[0]
    assert attachment.hashes["md5"]
    assert attachment.hashes["sha256"]
    assert len(attachment.hashes["sha256"]) == 64


def test_docx_attachment_size_nonzero(docx_email):
    assert docx_email.attachments[0].size > 0


def test_docx_body_url_found(docx_email):
    findings = extract_urls(docx_email)
    body_findings = [finding for finding in findings if finding.source == "body:plain"]
    assert len(body_findings) >= 1
    assert any("quarterly-docs" in finding.defanged_url for finding in body_findings)


def test_docx_attachment_urls_found(docx_email):
    findings = extract_urls(docx_email)
    docx_findings = [
        finding for finding in findings if finding.source == "attachment:report.docx"
    ]
    assert len(docx_findings) >= 3


def test_docx_paragraph_url_found(docx_email):
    findings = extract_urls(docx_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("malicious-docx-link" in url for url in all_urls)


def test_docx_support_url_found(docx_email):
    findings = extract_urls(docx_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("docx-support" in url for url in all_urls)


def test_docx_table_url_found(docx_email):
    findings = extract_urls(docx_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("docx-table-link" in url for url in all_urls)


def test_docx_total_url_count(docx_email):
    findings = extract_urls(docx_email)
    assert len(findings) == 4


def test_docx_all_urls_defanged(docx_email):
    for finding in extract_urls(docx_email):
        assert not finding.defanged_url.startswith("http")
        assert "[.]" in finding.defanged_url


def test_docx_process_file_output(tmp_path):
    result = process_file(DOCX_SAMPLE_PATH, tmp_path)
    assert result.success is True
    assert result.attachment_count == 1
    assert result.url_count == 4
    output_path = result.output_path
    assert (output_path / "attachments" / "report.docx").exists()
    urls_content = (output_path / "urls.txt").read_text(encoding="utf-8")
    assert "malicious-docx-link" in urls_content
    assert "docx-table-link" in urls_content
    assert "attachment:report.docx" in urls_content


# ---------------------------------------------------------------------------
# GROUP 26: xlsx_attachment.eml — XLSX URL extraction
# ---------------------------------------------------------------------------


def test_xlsx_email_parses(xlsx_email):
    assert xlsx_email is not None
    assert xlsx_email.subject == "Q1 Excel Report - Review Required"


def test_xlsx_has_one_attachment(xlsx_email):
    assert len(xlsx_email.attachments) == 1


def test_xlsx_attachment_filename(xlsx_email):
    assert xlsx_email.attachments[0].filename == "data.xlsx"


def test_xlsx_attachment_hashes_populated(xlsx_email):
    attachment = xlsx_email.attachments[0]
    assert attachment.hashes["md5"]
    assert attachment.hashes["sha256"]
    assert len(attachment.hashes["sha256"]) == 64


def test_xlsx_body_url_found(xlsx_email):
    findings = extract_urls(xlsx_email)
    body_findings = [finding for finding in findings if finding.source == "body:plain"]
    assert any("quarterly-docs" in finding.defanged_url for finding in body_findings)


def test_xlsx_attachment_urls_found(xlsx_email):
    findings = extract_urls(xlsx_email)
    xlsx_findings = [
        finding for finding in findings if finding.source == "attachment:data.xlsx"
    ]
    assert len(xlsx_findings) >= 2


def test_xlsx_malicious_url_found(xlsx_email):
    findings = extract_urls(xlsx_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("malicious-xlsx-link" in url for url in all_urls)


def test_xlsx_support_url_found(xlsx_email):
    findings = extract_urls(xlsx_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("xlsx-support" in url for url in all_urls)


def test_xlsx_total_url_count(xlsx_email):
    findings = extract_urls(xlsx_email)
    assert len(findings) == 3


def test_xlsx_all_urls_defanged(xlsx_email):
    for finding in extract_urls(xlsx_email):
        assert not finding.defanged_url.startswith("http")
        assert "[.]" in finding.defanged_url


def test_xlsx_process_file_output(tmp_path):
    result = process_file(XLSX_SAMPLE_PATH, tmp_path)
    assert result.success is True
    assert result.attachment_count == 1
    assert result.url_count == 3
    output_path = result.output_path
    assert (output_path / "attachments" / "data.xlsx").exists()
    urls_content = (output_path / "urls.txt").read_text(encoding="utf-8")
    assert "malicious-xlsx-link" in urls_content
    assert "attachment:data.xlsx" in urls_content


# ---------------------------------------------------------------------------
# GROUP 27: pptx_attachment.eml — PPTX URL extraction
# ---------------------------------------------------------------------------


def test_pptx_email_parses(pptx_email):
    assert pptx_email is not None
    assert pptx_email.subject == "Q1 PowerPoint Report - Review Required"


def test_pptx_has_one_attachment(pptx_email):
    assert len(pptx_email.attachments) == 1


def test_pptx_attachment_filename(pptx_email):
    assert pptx_email.attachments[0].filename == "slides.pptx"


def test_pptx_attachment_hashes_populated(pptx_email):
    attachment = pptx_email.attachments[0]
    assert attachment.hashes["md5"]
    assert attachment.hashes["sha256"]
    assert len(attachment.hashes["sha256"]) == 64


def test_pptx_body_url_found(pptx_email):
    findings = extract_urls(pptx_email)
    body_findings = [finding for finding in findings if finding.source == "body:plain"]
    assert any("quarterly-docs" in finding.defanged_url for finding in body_findings)


def test_pptx_attachment_urls_found(pptx_email):
    findings = extract_urls(pptx_email)
    pptx_findings = [
        finding for finding in findings if finding.source == "attachment:slides.pptx"
    ]
    assert len(pptx_findings) >= 2


def test_pptx_malicious_url_found(pptx_email):
    findings = extract_urls(pptx_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("malicious-pptx-link" in url for url in all_urls)


def test_pptx_support_url_found(pptx_email):
    findings = extract_urls(pptx_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("pptx-support" in url for url in all_urls)


def test_pptx_total_url_count(pptx_email):
    findings = extract_urls(pptx_email)
    assert len(findings) == 3


def test_pptx_all_urls_defanged(pptx_email):
    for finding in extract_urls(pptx_email):
        assert not finding.defanged_url.startswith("http")
        assert "[.]" in finding.defanged_url


def test_pptx_process_file_output(tmp_path):
    result = process_file(PPTX_SAMPLE_PATH, tmp_path)
    assert result.success is True
    assert result.attachment_count == 1
    assert result.url_count == 3
    output_path = result.output_path
    assert (output_path / "attachments" / "slides.pptx").exists()
    urls_content = (output_path / "urls.txt").read_text(encoding="utf-8")
    assert "malicious-pptx-link" in urls_content
    assert "attachment:slides.pptx" in urls_content


# ---------------------------------------------------------------------------
# GROUP 28: rtf_attachment.eml — RTF URL extraction
# ---------------------------------------------------------------------------


def test_rtf_email_parses(rtf_email):
    assert rtf_email is not None
    assert rtf_email.subject == "Q1 RTF Report - Review Required"


def test_rtf_has_one_attachment(rtf_email):
    assert len(rtf_email.attachments) == 1


def test_rtf_attachment_filename(rtf_email):
    assert rtf_email.attachments[0].filename == "report.rtf"


def test_rtf_attachment_content_type(rtf_email):
    assert "rtf" in rtf_email.attachments[0].content_type.lower()


def test_rtf_attachment_hashes_populated(rtf_email):
    attachment = rtf_email.attachments[0]
    assert attachment.hashes["md5"]
    assert attachment.hashes["sha256"]
    assert len(attachment.hashes["sha256"]) == 64


def test_rtf_attachment_size_nonzero(rtf_email):
    assert rtf_email.attachments[0].size > 0


def test_rtf_body_url_found(rtf_email):
    findings = extract_urls(rtf_email)
    body_findings = [finding for finding in findings if finding.source == "body:plain"]
    assert len(body_findings) >= 1
    assert any("quarterly-docs" in finding.defanged_url for finding in body_findings)


def test_rtf_attachment_urls_found(rtf_email):
    findings = extract_urls(rtf_email)
    rtf_findings = [
        finding for finding in findings if finding.source == "attachment:report.rtf"
    ]
    assert len(rtf_findings) >= 2


def test_rtf_malicious_url_found(rtf_email):
    findings = extract_urls(rtf_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("malicious-rtf-link" in url for url in all_urls)


def test_rtf_support_url_found(rtf_email):
    findings = extract_urls(rtf_email)
    all_urls = [finding.defanged_url for finding in findings]
    assert any("rtf-support" in url for url in all_urls)


def test_rtf_total_url_count(rtf_email):
    findings = extract_urls(rtf_email)
    assert len(findings) == 3


def test_rtf_all_urls_defanged(rtf_email):
    for finding in extract_urls(rtf_email):
        assert not finding.defanged_url.startswith("http")
        assert "[.]" in finding.defanged_url


def test_rtf_process_file_output(tmp_path):
    result = process_file(RTF_SAMPLE_PATH, tmp_path)
    assert result.success is True
    assert result.attachment_count == 1
    assert result.url_count == 3
    output_path = result.output_path
    assert (output_path / "attachments" / "report.rtf").exists()
    urls_content = (output_path / "urls.txt").read_text(encoding="utf-8")
    assert "malicious-rtf-link" in urls_content
    assert "attachment:report.rtf" in urls_content
