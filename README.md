# ThreatLens – Threat Intelligence & Analysis

Flask web app that validates Indicators of Compromise (IP, domain, URL, MD5/SHA-1/SHA-256),
enriches them with VirusTotal, gives an **evidence-based** risk label, and stores a history in SQLite.
For defensive research with authorised services and test data only.

## Features
- IOC format validation (accepts defanged input like `hxxp://evil[.]com`)
- VirusTotal v3 enrichment with safe handling of missing key, 404, rate limits, timeouts
- Risk labels: High / Medium / Low / Unknown / Not assessed (missing data is never "safe")
- SQLite investigation history, CSV export, clear history
- Indicators displayed defanged so they can't be clicked accidentally

## Setup
```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # add your VT_API_KEY (free key from virustotal.com)
python app.py                                         # http://127.0.0.1:5000
```
Without `VT_API_KEY` the app still runs; results show **Not assessed**.

## Tests
```bash
python -m pytest -v
```
See `docs/TEST_PLAN.md` for manual test cases and a table to fill with screenshots.

## Structure
```
app.py          Flask routes          validators.py  IOC detection/validation
vt_client.py    VirusTotal client     risk.py        Risk logic
db.py           SQLite layer          templates/     Bootstrap UI
tests/          pytest suite          docs/          Test plan
```

## Security notes
- API key only via environment variable; `.env` is git-ignored
- Parameterised SQL, Jinja autoescaping, input length cap, CSV formula-injection guard
- Debug mode off; set a strong `FLASK_SECRET_KEY`
- Respect VirusTotal free-tier limits (4 requests/min)
