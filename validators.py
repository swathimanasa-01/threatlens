"""IOC normalisation and format validation.
Format validation only checks syntax. It says nothing about maliciousness."""
import ipaddress
import re
from urllib.parse import urlparse

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def refang(value: str) -> str:
    """Convert defanged indicators (hxxp, [.]) back to normal form."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    return v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def is_domain(v: str) -> bool:
    return bool(DOMAIN_RE.match(v))


def is_url(v: str) -> bool:
    try:
        p = urlparse(v)
    except ValueError:
        return False
    if p.scheme.lower() not in ("http", "https", "ftp") or not p.hostname:
        return False
    return is_ip(p.hostname) or is_domain(p.hostname)


def detect_type(raw: str):
    """Return (normalised_value, type) where type is one of
    ip, domain, url, md5, sha1, sha256, or None if unsupported/invalid."""
    if not raw or not raw.strip():
        return "", None
    v = refang(raw)
    if len(v) > 2048:
        return v, None
    if HEX_RE.match(v) and len(v) in HASH_LENGTHS:
        return v.lower(), HASH_LENGTHS[len(v)]
    if is_ip(v):
        return str(ipaddress.ip_address(v)), "ip"
    if "://" in v:
        return v, ("url" if is_url(v) else None)
    if is_domain(v):
        return v.lower(), "domain"
    return v, None
