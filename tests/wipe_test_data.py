#!/usr/bin/env python3
"""Wipe test rows from pcbridge.db (keeps schema). Container must be running."""
import glob
import os
import sqlite3

DB = "/opt/pcbridge/data/pcbridge.db"
with sqlite3.connect(DB) as c:
    for t in ("tasks", "pairing_fails", "pairing_codes", "devices"):
        c.execute("DELETE FROM %s" % t)
for p in glob.glob("/opt/pcbridge/data/files/*"):
    os.remove(p)
print("test rows wiped, files dir emptied.")
