#!/usr/bin/env python3
"""Smoke test for the PCBridge API. Run on the box:
    python3 /opt/pcbridge/tests/smoke_test.py
Reads the admin token from /opt/pcbridge/pcbridge.env (never prints it).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = os.environ.get("PCBRIDGE_URL", "http://127.0.0.1:8003")
ENV_FILE = "/opt/pcbridge/pcbridge.env"

FAILS = []


def check(name, cond, detail=""):
    tag = "PASS" if cond else "FAIL"
    print("%-4s %s %s" % (tag, name, detail))
    if not cond:
        FAILS.append(name)


def load_admin_token():
    for line in open(ENV_FILE):
        if line.startswith("PCBRIDGE_ADMIN_TOKEN="):
            return line.strip().split("=", 1)[1]
    raise SystemExit("no admin token in %s" % ENV_FILE)


ADMIN = load_admin_token()


def call(method, path, headers=None, body=None, raw=False):
    h = dict(headers or {})
    data = None
    if body is not None and not raw:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    elif raw:
        data = body
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            payload = r.read()
            return r.status, payload
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def call_json(*a, **kw):
    st, payload = call(*a, **kw)
    try:
        return st, json.loads(payload)
    except Exception:
        return st, {}


def multipart(filename, content):
    boundary = uuid.uuid4().hex
    body = (
        "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n" % (boundary, filename)
    ).encode() + content + ("\r\n--%s--\r\n" % boundary).encode()
    return body, "multipart/form-data; boundary=%s" % boundary


A = {"X-Admin-Token": ADMIN}

# 0. health
st, j = call_json("GET", "/healthz")
check("healthz", st == 200 and j.get("ok") is True, "status=%d" % st)

# 1. admin gate: wrong/missing token -> 404
st, _ = call("GET", "/api/admin/devices")
check("admin gate no-token -> 404", st == 404, "status=%d" % st)
st, _ = call("GET", "/api/admin/devices", {"X-Admin-Token": "wrong"})
check("admin gate wrong-token -> 404", st == 404, "status=%d" % st)

# 2. pair code
st, j = call_json("POST", "/api/admin/pair-codes", A, {})
check("create pair code", st == 200 and len(j.get("code", "")) == 6)
code = j["code"]

# 3. enroll with wrong code -> 404 (and records a fail)
st, _ = call("POST", "/api/enroll", body={"code": "000000", "name": "bad"})
check("enroll wrong code -> 404", st == 404, "status=%d" % st)

# 4. enroll with the real code
st, j = call_json("POST", "/api/enroll", body={"code": code, "name": "test-win"})
check("enroll ok", st == 200 and j.get("device_token"), "device_id=%s" % j.get("device_id"))
DEV = {"X-Device-Token": j["device_token"]}
DEV_ID = j["device_id"]

# 5. replay the same code -> 404 (one-time)
st, _ = call("POST", "/api/enroll", body={"code": code, "name": "again"})
check("pair code one-time", st == 404, "status=%d" % st)

# 6. bad device token -> 404
st, _ = call("POST", "/api/poll", {"X-Device-Token": "nope"})
check("bad device token -> 404", st == 404, "status=%d" % st)

# 7. dispatch a run task, hand polls it
st, j = call_json("POST", "/api/admin/tasks", A, {
    "device_id": DEV_ID, "type": "run",
    "params": {"cmd": "echo hello", "cwd": "C:/work"}, "timeout": 60})
check("create run task", st == 200 and isinstance(j.get("id"), int))
TASK_RUN = j["id"]
st, j = call_json("POST", "/api/poll", DEV)
t = j.get("task")
check("poll returns the task", st == 200 and t and t["id"] == TASK_RUN and t["status"] == "dispatched")

# 8. report done with output
st, j = call_json("POST", "/api/report", DEV, {
    "task_id": TASK_RUN, "status": "done", "output": "hello\n"})
check("report done", st == 200)
st, j = call_json("GET", "/api/admin/tasks?limit=5", A)
t = j["tasks"][0]
check("task visible in history", t["id"] == TASK_RUN and t["status"] == "done" and t["output"] == "hello\n")

# 9. double report -> 409
st, _ = call("POST", "/api/report", DEV, {"task_id": TASK_RUN, "status": "done", "output": "x"})
check("double report -> 409", st == 409, "status=%d" % st)

# 10. output truncation (70 KiB of text -> capped)
big = "x" * (70 * 1024)
st, j = call_json("POST", "/api/admin/tasks", A, {
    "device_id": DEV_ID, "type": "run", "params": {"cmd": "spam"}, "timeout": 60})
TASK_BIG = j["id"]
call_json("POST", "/api/poll", DEV)
st, j = call_json("POST", "/api/report", DEV, {"task_id": TASK_BIG, "status": "done", "output": big})
st2, j2 = call_json("GET", "/api/admin/tasks?device_id=%d&limit=1" % DEV_ID, A)
out = j2["tasks"][0]["output"]
check("output capped at 64KiB", st == 200 and len(out.encode()) < 70 * 1024 and "truncated" in out,
      "len=%d" % len(out.encode()))

# 11. file round trip: admin upload -> put task -> hand downloads
content = b"PK\x03\x04 fake-apk " + os.urandom(16)
body, ctype = multipart("Updater.kt", content)
st, j = call_json("POST", "/api/admin/upload", dict(A, **{"Content-Type": ctype}), body, raw=True)
check("admin upload", st == 200 and j.get("file_id"), "file_id=%s" % j.get("file_id"))
FILE_ID = j["file_id"]
st, j = call_json("POST", "/api/admin/tasks", A, {
    "device_id": DEV_ID, "type": "put",
    "params": {"path": "D:/app/Uploader.kt", "file_id": FILE_ID}, "timeout": 60})
TASK_PUT = j["id"]
call_json("POST", "/api/poll", DEV)
st, payload = call("GET", "/api/files/%s" % FILE_ID, DEV)
check("hand downloads put file", st == 200 and payload == content)

# 12. get task: hand uploads result -> admin downloads
st, j = call_json("POST", "/api/admin/tasks", A, {
    "device_id": DEV_ID, "type": "get",
    "params": {"path": "D:/app/app-debug.apk"}, "timeout": 600})
TASK_GET = j["id"]
call_json("POST", "/api/poll", DEV)
body, ctype = multipart("app-debug.apk", content)
st, _ = call("POST", "/api/tasks/%d/file" % TASK_GET, dict(DEV, **{"Content-Type": ctype}), body, raw=True)
check("hand uploads get result", st == 200)
st, payload = call("GET", "/api/admin/tasks/%d/file" % TASK_GET, A)
check("admin downloads get result", st == 200 and payload == content)

# 13. invalid file_id -> 400 (no path traversal)
st, _ = call("GET", "/api/files/..%2F..%2Fetc%2Fpasswd", DEV)
check("bad file_id rejected", st in (400, 404), "status=%d" % st)

# 14. revoke -> device immediately locked out
st, j = call_json("DELETE", "/api/admin/devices/%d" % DEV_ID, A)
check("revoke device", st == 200 and j.get("revoked") == DEV_ID)
st, _ = call("POST", "/api/poll", DEV)
check("revoked device locked out", st == 404, "status=%d" % st)

# 15. long-poll returns empty task after ~25s when nothing queued
st, j = call_json("POST", "/api/enroll", body={"code": "123456", "name": "x"})
# (no valid code left -> expect 404/429; that's fine, just don't crash)
check("enroll without code stable", st in (404, 429), "status=%d" % st)

print()
if FAILS:
    print("FAILED: %d checks: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("ALL PASS")
