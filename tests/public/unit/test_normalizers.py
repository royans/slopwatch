import pytest
from slopwatch.core.normalizers import (
    normalize_email_address,
    normalize_email_domain,
    extract_clean_email_and_domain,
)


def test_normalize_email_address_various_formats():
    # RFC 2822 Formats
    assert normalize_email_address('"Ruben J. Jongejan" <ruben.jongejan@gmail.com>') == "ruben.jongejan@gmail.com"
    assert normalize_email_address("Anirhossein Daneshi Kohan <anirhossein6168@gmail.com>") == "anirhossein6168@gmail.com"
    assert normalize_email_address("b3b <ash.b3b@gmail.com>") == "ash.b3b@gmail.com"
    assert normalize_email_address("Chris Maillefaud <chrismaille@users.noreply.github.com>") == "chrismaille@users.noreply.github.com"
    assert normalize_email_address("Clean Energy Exchange <info@ceex.ch>") == "info@ceex.ch"
    
    # Bracketed & Mailto
    assert normalize_email_address("<dev@example.org>") == "dev@example.org"
    assert normalize_email_address("mailto:team@company.com") == "team@company.com"
    assert normalize_email_address("USER@DOMAIN.COM") == "user@domain.com"
    assert normalize_email_address("  foo@bar.com.  ") == "foo@bar.com"

    # Empty / Invalid
    assert normalize_email_address(None) is None
    assert normalize_email_address("") is None
    assert normalize_email_address("just_a_name") is None


def test_normalize_email_domain():
    # Extracts clean domains without trailing brackets
    assert normalize_email_domain("gmail.com>") == "gmail.com"
    assert normalize_email_domain("<gmail.com>") == "gmail.com"
    assert normalize_email_domain("users.noreply.github.com>") == "users.noreply.github.com"
    assert normalize_email_domain("ceex.ch>") == "ceex.ch"
    assert normalize_email_domain('"Ruben J. Jongejan" <ruben.jongejan@gmail.com>') == "gmail.com"
    assert normalize_email_domain("foo@sub.domain.co.uk") == "sub.domain.co.uk"


def test_extract_clean_email_and_domain():
    email, domain = extract_clean_email_and_domain('"Ruben J. Jongejan" <ruben.jongejan@gmail.com>')
    assert email == "ruben.jongejan@gmail.com"
    assert domain == "gmail.com"

    email2, domain2 = extract_clean_email_and_domain("Clean Energy Exchange <info@ceex.ch>")
    assert email2 == "info@ceex.ch"
    assert domain2 == "ceex.ch"
