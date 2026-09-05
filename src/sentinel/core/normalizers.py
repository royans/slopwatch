"""
Sentinel Normalization Utilities.

Provides robust extraction and normalization for email addresses, domains,
package names, and metadata strings.
"""

import re
import email.utils
from typing import Optional, Tuple

EMAIL_REGEX = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
DOMAIN_REGEX = re.compile(r"^([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def normalize_email_address(raw_email: Optional[str]) -> Optional[str]:
    """
    Extract and normalize a clean, lowercase email address from raw inputs
    such as 'John Doe <john@example.com>', '<john@example.com>', or 'mailto:john@example.com'.
    """
    if not raw_email:
        return None

    cleaned = str(raw_email).strip()
    if not cleaned:
        return None

    # Strip mailto: prefix if present
    if cleaned.lower().startswith("mailto:"):
        cleaned = cleaned[7:].strip()

    # 1. Try standard RFC 2822 parsing (handles "Name <email@domain.com>")
    _, parsed_email = email.utils.parseaddr(cleaned)
    if parsed_email and "@" in parsed_email:
        parsed_email = parsed_email.strip("<>\"' \t\r\n.").lower()
        if "@" in parsed_email:
            return parsed_email

    # 2. Regex fallback search
    match = EMAIL_REGEX.search(cleaned)
    if match:
        email_str = match.group(1).strip("<>\"' \t\r\n.").lower()
        return email_str

    return None


def normalize_email_domain(raw_input: Optional[str]) -> Optional[str]:
    """
    Extract and normalize a clean email domain from an email address or raw domain string.
    Removes trailing brackets (e.g. 'gmail.com>' -> 'gmail.com'), quotes, and invalid characters.
    """
    if not raw_input:
        return None

    cleaned = str(raw_input).strip()
    if not cleaned:
        return None

    # If it's a full email or has '@', get the portion after '@'
    if "@" in cleaned:
        clean_email = normalize_email_address(cleaned)
        if clean_email and "@" in clean_email:
            cleaned = clean_email.split("@")[-1]
        else:
            cleaned = cleaned.split("@")[-1]

    # Clean domain string of brackets, quotes, trailing dots/whitespace
    domain = cleaned.strip("<>\"' \t\r\n/\\;:,").lower()
    
    # Remove trailing punctuation or brackets if any remain
    domain = re.sub(r"[>\)\]\.\s]+$", "", domain)

    if not domain or "." not in domain or len(domain) < 4:
        return None

    # Validate against basic domain structure
    if DOMAIN_REGEX.match(domain):
        return domain

    # Fallback cleanup for subdomains
    domain_match = re.search(r"([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", domain)
    if domain_match:
        cand = domain_match.group(1).strip(".").lower()
        if "." in cand and len(cand) >= 4:
            return cand

    return None


def extract_clean_email_and_domain(raw_email: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Simultaneously extracts clean normalized email address and normalized domain.
    Example: '"Ruben J. Jongejan" <ruben.jongejan@gmail.com>' -> ('ruben.jongejan@gmail.com', 'gmail.com')
    """
    clean_email = normalize_email_address(raw_email)
    clean_domain = normalize_email_domain(clean_email or raw_email)
    return clean_email, clean_domain
