"""PCBridge server — cloud brain <-> dumb hands.

API surface (DESIGN.md v1):
  hand side   (auth: X-Device-Token):
    POST /api/enroll                 {code, name} -> {device_id, device_token}
    POST /api/poll                   long-poll for next task
    POST /api/report                 {task_id, status, output}
    GET  /api/files/<file_id>        download file for a `put` task
    POST /api/tasks/<task_id>/file   upload result file for a `get` task
  console/brain side (auth: X-Admin-Token):
    POST /api/admin/pair-codes       -> {code, expires}
    GET  /api/admin/devices          list
    DELETE /api/admin/devices/<id>   revoke
    POST /api/admin/tasks            {device_id, type, params, timeout}
    GET  /api/admin/tasks[?device_id=&limit=]
    GET  /api/admin/tasks/<id>/file  download file the hand uploaded
    POST /api/admin/upload           upload file (for `put` tasks) -> {file_id}
    GET  /api/admin/files/<file_id>  download
  public:
    GET  /healthz

Hard rules (from earlier incidents):
  tokens/codes never in URLs, never in logs;
  server stores only SHA-256 hashes of device tokens;
  output capped at 64 KiB per report.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from functools import wraps

from flask import Flask, abort, g, jsonify, make_response, request, render_template, send_file

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "pcbridge.db")
FILES_DIR = os.path.join(DATA_DIR, "files")
ADMIN_TOKEN = os.environ.get("PCBRIDGE_ADMIN_TOKEN", "")

OUTPUT_CAP = 64 * 1024          # per-report output cap (DESIGN.md 一)
FILE_CAP = 300 * 1024 * 1024    # file transfer cap
POLL_WAIT = 25                  # long-poll seconds
CODE_TTL = 600                  # pairing code lifetime
MAX_FAILS = 3                   # wrong codes within window before lockout
FAIL_WINDOW = 600
ONLINE_WINDOW = 60
INTERRUPT_GRACE = 120     # dispatched task with no report for timeout+this -> interrupted
TASK_TYPES = {"run", "put", "get"}
REPORT_STATUSES = {"done", "failed", "rejected"}

FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")

app = Flask(__name__)
os.makedirs(FILES_DIR, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT 'device',
    token_hash TEXT NOT NULL UNIQUE,
    created REAL NOT NULL,
    last_seen REAL NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pairing_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash TEXT NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    used_by INTEGER
);
CREATE TABLE IF NOT EXISTS pairing_fails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    params TEXT NOT NULL,
    timeout INTEGER NOT NULL DEFAULT 600,
    status TEXT NOT NULL DEFAULT 'queued',
    output TEXT NOT NULL DEFAULT '',
    file_path TEXT,
    created REAL NOT NULL,
    dispatched REAL,
    finished REAL
);
CREATE INDEX IF NOT EXISTS idx_tasks_dev_status ON tasks (device_id, status);
"""


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    with sqlite3.connect(DB_PATH) as c:
        c.executescript(SCHEMA)


init_db()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


# ---------- auth ----------

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # no admin token configured, or mismatch -> pretend the route
        # does not exist (same pattern as the diary app's admin gate)
        tok = request.headers.get("X-Admin-Token", "")
        if not ADMIN_TOKEN or not hmac.compare_digest(tok, ADMIN_TOKEN):
            abort(404)
        return f(*args, **kwargs)

    return wrapper


def device_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        tok = request.headers.get("X-Device-Token", "")
        if not tok:
            abort(401)
        db = get_db()
        row = db.execute(
            "SELECT * FROM devices WHERE token_hash=? AND revoked=0",
            (sha256_hex(tok),),
        ).fetchone()
        if row is None:
            abort(404)
        db.execute(
            "UPDATE devices SET last_seen=? WHERE id=?", (time.time(), row["id"])
        )
        db.commit()
        g.device = row
        return f(*args, **kwargs)

    return wrapper


# ---------- helpers ----------

def truncate_output(text):
    raw = (text or "").encode("utf-8", "replace")
    if len(raw) <= OUTPUT_CAP:
        return text or ""
    return raw[:OUTPUT_CAP].decode("utf-8", "replace") + "\n[output truncated at 64KiB]"


def task_dict(row):
    d = {
        "id": row["id"],
        "device_id": row["device_id"],
        "type": row["type"],
        "params": json.loads(row["params"]),
        "timeout": row["timeout"],
        "status": row["status"],
        "output": row["output"],
        "created": row["created"],
        "dispatched": row["dispatched"],
        "finished": row["finished"],
        "has_file": bool(row["file_path"]),
    }
    return d


# ---------- public ----------

@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "pcbridge"}


# ---------- hand side ----------

@app.post("/api/enroll")
def enroll():
    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip()
    name = str(data.get("name", "")).strip()[:40] or "device"
    if not (code.isdigit() and len(code) == 6):
        abort(400)

    db = get_db()
    now = time.time()
    fails = db.execute(
        "SELECT COUNT(*) AS n FROM pairing_fails WHERE ts > ?", (now - FAIL_WINDOW,)
    ).fetchone()["n"]
    if fails >= MAX_FAILS:
        abort(429)  # too many wrong codes recently

    row = db.execute(
        "SELECT * FROM pairing_codes WHERE code_hash=? AND used_by IS NULL",
        (sha256_hex(code),),
    ).fetchone()
    if row is None or row["expires"] < now:
        db.execute("INSERT INTO pairing_fails (ts) VALUES (?)", (now,))
        db.commit()
        abort(404)

    token = secrets.token_urlsafe(32)
    cur = db.execute(
        "INSERT INTO devices (name, token_hash, created, last_seen) VALUES (?,?,?,?)",
        (name, sha256_hex(token), now, now),
    )
    dev_id = cur.lastrowid
    db.execute("UPDATE pairing_codes SET used_by=? WHERE id=?", (dev_id, row["id"]))
    db.commit()
    return {"device_id": dev_id, "device_token": token, "name": name}


@app.post("/api/poll")
@device_required
def poll():
    db = get_db()
    dev_id = g.device["id"]
    deadline = time.time() + POLL_WAIT
    while True:
        now = time.time()
        # a hand that died mid-task leaves a dispatched task behind;
        # mark it interrupted so the brain can decide to retry (DESIGN.md 一)
        db.execute(
            "UPDATE tasks SET status='interrupted', finished=? "
            "WHERE device_id=? AND status='dispatched' AND dispatched + timeout + ? < ?",
            (now, dev_id, INTERRUPT_GRACE, now),
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM tasks WHERE device_id=? AND status='queued' ORDER BY id LIMIT 1",
            (dev_id,),
        ).fetchone()
        if row is not None:
            now = time.time()
            db.execute(
                "UPDATE tasks SET status='dispatched', dispatched=? WHERE id=?",
                (now, row["id"]),
            )
            db.commit()
            row = db.execute("SELECT * FROM tasks WHERE id=?", (row["id"],)).fetchone()
            return jsonify({"task": task_dict(row)})
        if time.time() >= deadline:
            return jsonify({"task": None})
        time.sleep(0.5)


@app.post("/api/report")
@device_required
def report():
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in REPORT_STATUSES:
        abort(400)
    task_id = data.get("task_id")
    if not isinstance(task_id, int):
        abort(400)
    db = get_db()
    row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if row is None or row["device_id"] != g.device["id"]:
        abort(404)
    if row["status"] not in ("dispatched", "interrupted"):
        abort(409)
    db.execute(
        "UPDATE tasks SET status=?, output=?, finished=? WHERE id=?",
        (status, truncate_output(str(data.get("output", ""))), time.time(), task_id),
    )
    db.commit()
    return {"ok": True}


@app.get("/api/files/<file_id>")
@device_required
def device_get_file(file_id):
    if not FILE_ID_RE.match(file_id):
        abort(400)
    path = os.path.join(FILES_DIR, file_id)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=file_id)


@app.post("/api/tasks/<int:task_id>/file")
@device_required
def device_upload_result(task_id):
    f = request.files.get("file")
    if f is None or not f.filename:
        abort(400)
    db = get_db()
    row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if row is None or row["device_id"] != g.device["id"]:
        abort(404)
    if row["type"] != "get":
        abort(409)
    safe_name = os.path.basename(f.filename)[:80] or "result.bin"
    stored = os.path.join(FILES_DIR, "task-%d-%s" % (task_id, safe_name))
    f.save(stored)
    if os.path.getsize(stored) > FILE_CAP:
        os.remove(stored)
        abort(413)
    db.execute("UPDATE tasks SET file_path=? WHERE id=?", (stored, task_id))
    db.commit()
    return {"ok": True, "name": safe_name}


# ---------- console / brain side ----------

def issue_pair_code():
    code = "%06d" % secrets.randbelow(1000000)
    now = time.time()
    db = get_db()
    db.execute(
        "INSERT INTO pairing_codes (code_hash, created, expires) VALUES (?,?,?)",
        (sha256_hex(code), now, now + CODE_TTL),
    )
    db.commit()
    return {"code": code, "expires": now + CODE_TTL, "ttl": CODE_TTL}


@app.post("/api/admin/pair-codes")
@admin_required
def admin_pair_code():
    return issue_pair_code()


@app.get("/api/admin/devices")
@admin_required
def admin_devices():
    now = time.time()
    rows = get_db().execute("SELECT * FROM devices ORDER BY id").fetchall()
    return {
        "devices": [
            {
                "id": r["id"],
                "name": r["name"],
                "created": r["created"],
                "last_seen": r["last_seen"],
                "online": (not r["revoked"]) and (now - r["last_seen"] < ONLINE_WINDOW),
                "revoked": bool(r["revoked"]),
            }
            for r in rows
        ]
    }


@app.delete("/api/admin/devices/<int:device_id>")
@admin_required
def admin_revoke(device_id):
    db = get_db()
    cur = db.execute("UPDATE devices SET revoked=1 WHERE id=?", (device_id,))
    db.commit()
    return {"ok": cur.rowcount == 1, "revoked": device_id}


@app.post("/api/admin/tasks")
@admin_required
def admin_create_task():
    data = request.get_json(silent=True) or {}
    t = data.get("type")
    if t not in TASK_TYPES:
        abort(400)
    device_id = data.get("device_id")
    if not isinstance(device_id, int):
        abort(400)
    db = get_db()
    dev = db.execute(
        "SELECT id FROM devices WHERE id=? AND revoked=0", (device_id,)
    ).fetchone()
    if dev is None:
        abort(404)
    params = data.get("params")
    if not isinstance(params, dict):
        abort(400)
    timeout = data.get("timeout", 600)
    if not isinstance(timeout, int) or not (1 <= timeout <= 3600):
        abort(400)
    cur = db.execute(
        "INSERT INTO tasks (device_id, type, params, timeout, created) VALUES (?,?,?,?,?)",
        (device_id, t, json.dumps(params, ensure_ascii=False), timeout, time.time()),
    )
    db.commit()
    return {"id": cur.lastrowid, "status": "queued"}


@app.get("/api/admin/tasks")
@admin_required
def admin_tasks():
    limit = min(int(request.args.get("limit", 50)), 200)
    q = "SELECT * FROM tasks"
    args = []
    if request.args.get("device_id"):
        q += " WHERE device_id=?"
        args.append(int(request.args["device_id"]))
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    rows = get_db().execute(q, args).fetchall()
    return {"tasks": [task_dict(r) for r in rows]}


@app.get("/api/admin/tasks/<int:task_id>/file")
@admin_required
def admin_task_file(task_id):
    row = get_db().execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if row is None or not row["file_path"] or not os.path.isfile(row["file_path"]):
        abort(404)
    return send_file(row["file_path"], as_attachment=True)


@app.post("/api/admin/upload")
@admin_required
def admin_upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        abort(400)
    file_id = uuid.uuid4().hex
    path = os.path.join(FILES_DIR, file_id)
    f.save(path)
    if os.path.getsize(path) > FILE_CAP:
        os.remove(path)
        abort(413)
    return {"file_id": file_id, "name": os.path.basename(f.filename)[:80]}


@app.get("/api/admin/files/<file_id>")
@admin_required
def admin_get_file(file_id):
    if not FILE_ID_RE.match(file_id):
        abort(400)
    path = os.path.join(FILES_DIR, file_id)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=file_id)


# ---------- web console ----------
# Cookie gate: missing/wrong cookie -> 404, same cloak as the admin API.
# All console URLs live under /console/ and pages use RELATIVE links, so the
# console works both behind the /pb/ reverse-proxy prefix and on its own host.
CONSOLE_COOKIE = "pc_admin"


def console_authed():
    tok = request.cookies.get(CONSOLE_COOKIE, "")
    return bool(ADMIN_TOKEN) and hmac.compare_digest(tok, ADMIN_TOKEN)


def console_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not console_authed():
            abort(404)
        return f(*args, **kwargs)

    return wrapper


def console_redirect():
    resp = make_response("", 302)
    resp.headers["Location"] = "./"
    return resp


@app.template_filter("ts")
def fmt_ts(v):
    if not v:
        return "-"
    return time.strftime("%m-%d %H:%M:%S", time.localtime(v))


def console_index(code=None):
    db = get_db()
    now = time.time()
    devices = []
    for r in db.execute("SELECT * FROM devices ORDER BY id DESC").fetchall():
        d = dict(r)
        d["online"] = (not d["revoked"]) and (now - d["last_seen"]) < ONLINE_WINDOW
        devices.append(d)
    tasks = [
        task_dict(r)
        for r in db.execute("SELECT * FROM tasks ORDER BY id DESC LIMIT 50").fetchall()
    ]
    return render_template("index.html", devices=devices, tasks=tasks, code=code)


@app.get("/console")
def console_root():
    resp = make_response("", 302)
    resp.headers["Location"] = "console/"
    return resp


@app.get("/console/")
def console_home():
    if not console_authed():
        return render_template("login.html")
    return console_index()


@app.post("/console/login")
def console_login():
    tok = (request.form.get("token") or "").strip()
    if not ADMIN_TOKEN or not hmac.compare_digest(tok, ADMIN_TOKEN):
        abort(404)
    resp = console_redirect()
    resp.set_cookie(CONSOLE_COOKIE, tok, httponly=True, samesite="Lax")
    return resp


@app.post("/console/logout")
def console_logout():
    resp = console_redirect()
    resp.delete_cookie(CONSOLE_COOKIE)
    return resp


@app.post("/console/pair-code")
@console_required
def console_pair_code():
    r = issue_pair_code()
    return console_index(code=r["code"])


@app.post("/console/revoke")
@console_required
def console_revoke():
    dev_id = request.form.get("device_id", type=int)
    if dev_id:
        db = get_db()
        db.execute("UPDATE devices SET revoked=1 WHERE id=?", (dev_id,))
        db.commit()
    return console_redirect()


@app.get("/console/tasks/<int:task_id>")
@console_required
def console_task(task_id):
    row = get_db().execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if row is None:
        abort(404)
    t = task_dict(row)
    return render_template(
        "task.html",
        t=t,
        params_pretty=json.dumps(t["params"], ensure_ascii=False, indent=2),
        has_file=bool(row["file_path"]),
    )


@app.get("/console/tasks/<int:task_id>/file")
@console_required
def console_task_file(task_id):
    row = get_db().execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if row is None or not row["file_path"] or not os.path.isfile(row["file_path"]):
        abort(404)
    return send_file(row["file_path"], as_attachment=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8003)
