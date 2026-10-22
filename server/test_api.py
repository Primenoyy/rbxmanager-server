import os
import re
import sys
import tempfile

db_path = os.path.join(tempfile.gettempdir(), "rbxmanager_smoke.db")
if os.path.exists(db_path):
    os.remove(db_path)

os.environ["DATABASE_URL"] = "sqlite:///" + db_path.replace("\\", "/")
os.environ["ADMIN_SECRET"] = "test-secret"

from fastapi.testclient import TestClient
from app.main import app

ADMIN = {"X-Admin-Secret": "test-secret"}
ok = 0
fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print("  PASS", name)
    else:
        fail += 1
        print("  FAIL", name, extra)


with TestClient(app) as c:
    r = c.get("/health")
    check("health", r.status_code == 200, r.text)

    r = c.post("/admin/generate-keys", json={"count": 3, "duration_days": 30}, headers=ADMIN)
    check("generate keys", r.status_code == 200 and len(r.json()["keys"]) == 3, r.text)
    keys = r.json()["keys"]
    check("key format", all(re.fullmatch(r"RXBM-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", k) for k in keys), str(keys))

    r = c.post("/admin/generate-keys", json={"count": 1, "duration_days": 30}, headers={"X-Admin-Secret": "nope"})
    check("admin rejects bad secret", r.status_code == 403, r.text)

    r = c.post("/auth/register", json={"username": "tester", "password": "hunter2!"})
    check("register", r.status_code == 200 and r.json()["username"] == "tester", r.text)

    r = c.post("/auth/register", json={"username": "tester", "password": "hunter2!"})
    check("duplicate username 409", r.status_code == 409, r.text)

    r = c.get("/auth/check-username?username=newguy")
    check("username available", r.json()["available"] is True, r.text)
    r = c.get("/auth/check-username?username=tester")
    check("username taken", r.json()["available"] is False, r.text)

    r = c.post("/auth/login", json={"username": "tester", "password": "wrong"})
    check("bad password 401", r.status_code == 401, r.text)

    r = c.post("/auth/login", json={"username": "tester", "password": "hunter2!"})
    check("login", r.status_code == 200 and len(r.json()["token"]) > 20, r.text)
    token = r.json()["token"]
    auth = {"Authorization": "Bearer " + token}

    r = c.post("/license/activate", json={"key": keys[0], "hwid": "MACHINE-A"}, headers=auth)
    check("activate", r.status_code == 200 and r.json()["valid"] and r.json()["days_remaining"] == 30, r.text)

    r = c.post("/license/activate", json={"key": keys[1], "hwid": "MACHINE-B"}, headers=auth)
    check("activate second key", r.status_code == 200, r.text)

    r = c.post("/license/validate", json={"key": keys[0], "hwid": "MACHINE-A"})
    check("validate ok", r.status_code == 200 and r.json()["valid"] is True, r.text)

    r = c.get("/license/mine", headers=auth)
    check("my license", r.status_code == 200 and r.json()["key"] == keys[0], r.text)

    r = c.post("/license/validate", json={"key": keys[0], "hwid": "OTHER-PC"})
    check("validate hwid mismatch", r.json()["valid"] is False, r.text)

    r = c.post("/license/validate", json={"key": "RXBM-AAAA-BBBB-CCCC", "hwid": "x"})
    check("validate unknown", r.json()["valid"] is False, r.text)

    r = c.get("/admin/keys", headers=ADMIN)
    check("admin keys", r.status_code == 200 and len(r.json()) == 3, r.text)
    row = [k for k in r.json() if k["key"] == keys[0]][0]
    check("key bound to user", row["user_id"] is not None and row["hwid"] == "MACHINE-A", str(row))

    r = c.delete("/admin/revoke/" + keys[0], headers=ADMIN)
    check("revoke", r.status_code == 200 and r.json()["revoked"] is True, r.text)

    r = c.post("/license/validate", json={"key": keys[0], "hwid": "MACHINE-A"})
    check("validate revoked", r.json()["valid"] is False and "voqu" in r.json()["message"], r.text)

    r = c.post("/license/validate", json={"key": keys[2], "hwid": "MACHINE-C"})
    check("validate not activated", r.json()["valid"] is False, r.text)

    r = c.post("/auth/logout", headers=auth)
    check("logout", r.status_code == 200 and r.json()["success"] is True, r.text)
    r = c.post("/license/activate", json={"key": keys[1], "hwid": "X"}, headers=auth)
    check("session dead after logout", r.status_code == 401, r.text)

print("\n%d passed, %d failed" % (ok, fail))
sys.exit(1 if fail else 0)
