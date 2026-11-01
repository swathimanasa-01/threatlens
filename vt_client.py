"""VirusTotal v3 client with safe error handling. Never raises to the caller."""
import base64
import os
import requests

BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 15


def _endpoint(ioc: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        return f"{BASE}/ip_addresses/{ioc}"
    if ioc_type == "domain":
        return f"{BASE}/domains/{ioc}"
    if ioc_type in ("md5", "sha1", "sha256"):
        return f"{BASE}/files/{ioc}"
    if ioc_type == "url":
        uid = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        return f"{BASE}/urls/{uid}"
    raise ValueError("unsupported type")


def lookup(ioc: str, ioc_type: str, api_key: str | None = None) -> dict:
    """Returns {'status': ok|not_found|no_api_key|rate_limited|error,
                'stats': dict|None, 'details': dict, 'message': str}"""
    api_key = api_key or os.getenv("VT_API_KEY")
    if not api_key:
        return {"status": "no_api_key", "stats": None, "details": {},
                "message": "No VT_API_KEY configured. Reputation not checked."}
    try:
        r = requests.get(_endpoint(ioc, ioc_type),
                         headers={"x-apikey": api_key}, timeout=TIMEOUT)
    except requests.RequestException as exc:
        return {"status": "error", "stats": None, "details": {},
                "message": f"Service unreachable ({type(exc).__name__})."}
    if r.status_code == 404:
        return {"status": "not_found", "stats": None, "details": {},
                "message": "VirusTotal has no record of this indicator."}
    if r.status_code == 429:
        return {"status": "rate_limited", "stats": None, "details": {},
                "message": "API rate limit reached. Try again later."}
    if r.status_code in (401, 403):
        return {"status": "error", "stats": None, "details": {},
                "message": "API key rejected."}
    if r.status_code != 200:
        return {"status": "error", "stats": None, "details": {},
                "message": f"Unexpected response (HTTP {r.status_code})."}
    try:
        attrs = r.json()["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        return {"status": "error", "stats": None, "details": {},
                "message": "Malformed response from service."}
    stats = attrs.get("last_analysis_stats")
    details = {k: attrs.get(k) for k in
               ("reputation", "country", "as_owner", "registrar",
                "meaningful_name", "type_description", "last_analysis_date")
               if attrs.get(k) is not None}
    return {"status": "ok", "stats": stats, "details": details,
            "message": "Reputation data retrieved."}
