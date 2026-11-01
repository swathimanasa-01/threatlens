import csv
import io
import json
import os

from dotenv import load_dotenv
from flask import (Flask, Response, flash, redirect, render_template,
                   request, url_for)

import db
import risk
import validators
import vt_client

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")
db.init_db()


def defang(v: str) -> str:
    """Display-safe form so URLs/domains are not clickable."""
    return v.replace("http", "hxxp").replace(".", "[.]")


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        ioc, ioc_type = validators.detect_type(request.form.get("ioc", ""))
        if ioc_type is None:
            flash("Invalid or unsupported indicator. Supported: IPv4/IPv6, "
                  "domain, URL, MD5, SHA-1, SHA-256.", "danger")
        else:
            intel = vt_client.lookup(ioc, ioc_type)
            label, explanation = risk.assess(intel)
            db.save(ioc, ioc_type, label, explanation, intel)
            result = {"ioc": ioc, "display": defang(ioc), "type": ioc_type,
                      "risk": label, "explanation": explanation,
                      "status": intel["status"], "stats": intel["stats"],
                      "details": intel["details"]}
    return render_template("index.html", result=result)


@app.route("/history")
def history():
    rows = db.history()
    return render_template("history.html", rows=rows, defang=defang)


@app.route("/history/export.csv")
def export_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "ioc", "type", "risk", "summary"])
    for r in db.history(10000):
        # prefix to prevent CSV/formula injection when opened in Excel
        ioc = r["ioc"]
        if ioc[:1] in "=+-@":
            ioc = "'" + ioc
        w.writerow([r["timestamp"], ioc, r["ioc_type"], r["risk"], r["summary"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=threatlens_history.csv"})


@app.route("/history/clear", methods=["POST"])
def clear_history():
    db.clear()
    flash("History cleared.", "info")
    return redirect(url_for("history"))


if __name__ == "__main__":
    app.run(debug=False)
