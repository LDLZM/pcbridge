#!/usr/bin/env python3
"""Issue a pairing code via the admin API. Reads the admin token from
pcbridge.env; prints ONLY the short-lived code (never the token)."""
import json
import urllib.request

token = None
for line in open("/opt/pcbridge/pcbridge.env"):
    if line.startswith("PCBRIDGE_ADMIN_TOKEN="):
        token = line.strip().split("=", 1)[1]
assert token

req = urllib.request.Request(
    "http://127.0.0.1:8003/api/admin/pair-codes",
    data=b"{}",
    headers={"X-Admin-Token": token, "Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=10) as r:
    j = json.loads(r.read())
print("配对码:", j["code"], "（%d 分钟内有效，一次性）" % (j["ttl"] // 60))
