import db, app as appmod


def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t.db"))
    db.init_db()
    monkeypatch.delenv("VT_API_KEY", raising=False)
    return appmod.app.test_client()


def test_invalid_input_rejected(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.post("/", data={"ioc": "not valid"})
    assert b"Invalid or unsupported" in r.data


def test_no_key_graceful_and_saved(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.post("/", data={"ioc": "8.8.8.8"})
    assert r.status_code == 200 and b"Not assessed" in r.data
    assert b"8[.]8[.]8[.]8" in c.get("/history").data


def test_csv_export(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    c.post("/", data={"ioc": "example.com"})
    assert b"example.com" in c.get("/history/export.csv").data
