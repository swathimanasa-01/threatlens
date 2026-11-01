"""Evidence-based risk labelling. Missing data is never treated as safe."""

def assess(result: dict) -> tuple[str, str]:
    """Return (risk_label, explanation)."""
    if result.get("status") != "ok":
        label = "Not assessed" if result["status"] in (
            "no_api_key", "rate_limited", "error") else "Unknown"
        return label, result.get("message", "")
    stats = result.get("stats") or {}
    mal = int(stats.get("malicious", 0))
    sus = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) if stats else 0
    if total == 0:
        return "Unknown", "Service returned no analysis results."
    if mal >= 5:
        return "High", f"{mal} of {total} engines flagged this as malicious."
    if mal >= 1 or sus >= 1:
        return "Medium", (f"{mal} malicious and {sus} suspicious detections "
                          f"out of {total} engines. Manual review advised.")
    return "Low", (f"No detections among {total} engines. This is not proof "
                   "of safety.")
