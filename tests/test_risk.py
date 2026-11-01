from risk import assess


def test_no_key_not_assessed():
    assert assess({"status": "no_api_key", "message": "x"})[0] == "Not assessed"

def test_not_found_unknown():
    assert assess({"status": "not_found", "message": "x"})[0] == "Unknown"

def test_high():
    assert assess({"status": "ok", "stats": {"malicious": 9, "harmless": 60}})[0] == "High"

def test_medium():
    assert assess({"status": "ok", "stats": {"malicious": 1, "harmless": 60}})[0] == "Medium"

def test_low_not_called_safe():
    label, msg = assess({"status": "ok", "stats": {"malicious": 0, "suspicious": 0, "harmless": 70}})
    assert label == "Low" and "not proof" in msg

def test_empty_stats_unknown():
    assert assess({"status": "ok", "stats": {}})[0] == "Unknown"
