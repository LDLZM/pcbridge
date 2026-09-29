#!/usr/bin/env python3
"""Bootstrap: generate a random admin token into pcbridge.env (600) without
printing it anywhere. Run once before the first `docker compose up`."""
import os
import secrets

ENV_FILE = "/opt/pcbridge/pcbridge.env"
if os.path.exists(ENV_FILE):
    print("pcbridge.env already exists, not touching it.")
    raise SystemExit(0)
fd = os.open(ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("PCBRIDGE_ADMIN_TOKEN=%s\n" % secrets.token_urlsafe(32))
print("written %s (600), token not displayed." % ENV_FILE)
