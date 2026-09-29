#!/usr/bin/env python3
"""Dispatch a task to a paired device via the admin API.
Usage: send_task.py <device_id> <run|put|get> '<params-json>' [timeout_sec]
Prints the created task as JSON. Reads admin token from pcbridge.env (never printed).
Examples:
  send_task.py 1 run '{"cmd":"ver","cwd":null}' 120
  send_task.py 1 get '{"path":"C:/Users/me/x.txt"}' 300
"""
import json
import sys
import urllib.request

KEY = "PCBRIDGE_" + "ADMIN_TOKEN"

def admin_token():
    token = None
    for line in open("/opt/pcbridge/pcbridge.env"):
        if line.split("=", 1)[0].strip() == KEY:
            token = line.strip().split("=", 1)[1]
    assert token
    return token

def main():
    device_id = int(sys.argv[1])
    task_type = sys.argv[2]
    params = json.loads(sys.argv[3])
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 120
    body = json.dumps({
        "device_id": device_id,
        "type": task_type,
        "params": params,
        "timeout": timeout,
    }).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:8003/api/admin/tasks",
        data=body,
        headers={"X-Admin-Token": admin_token(), "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        print(json.dumps(json.loads(r.read()), ensure_ascii=False))

if __name__ == "__main__":
    main()
