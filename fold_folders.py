#!/usr/bin/env python3
"""Onboarding helper: fold the folders your old filters fed into Later, then delete them.

Old filter folders (Bulk, Newsletters, Banking, ...) stop receiving mail once you drop
the filters in favour of mail-triage. This moves their contents into Later and removes
each folder only after it reads back EMPTY. Nothing is deleted, and you name every
folder explicitly: there is no "everything" mode, so your real folders are safe.

  fold_folders.py ACCOUNT FOLDER [FOLDER ...]            dry run: counts only
  fold_folders.py ACCOUNT FOLDER [FOLDER ...] --apply    do it

ACCOUNT is the `user` of an account in config.yaml. Gmail labels work too: moving out of
a label removes that label, and the mail keeps its other labels and stays in All Mail.
"""
import os
import sys
import time
from pathlib import Path

from imapclient import IMAPClient

import triage

BATCH = 500


def main(argv):
    apply = "--apply" in argv
    args = [a for a in argv if a != "--apply"]
    if len(args) < 2:
        raise SystemExit(__doc__)
    user, folders = args[0], args[1:]
    here = Path(__file__).resolve().parent
    cfg = triage.load_config(os.environ.get("TRIAGE_CONFIG", here / "config.yaml"))
    spec = next((a for a in cfg["accounts"] if a["user"] == user), None)
    if not spec:
        raise SystemExit(f"{user} is not in config.yaml")
    later = cfg["later_folder"]
    if later in folders or "INBOX" in [f.upper() for f in folders]:
        raise SystemExit(f"refusing to fold INBOX or {later} itself")

    def connect():
        c = IMAPClient(spec["host"], port=spec.get("port", 993), ssl=True, timeout=300)
        c.login(user, os.environ[spec["password_env"]])
        return c

    c = connect()
    for f in folders:
        if not c.folder_exists(f):
            raise SystemExit(f"no folder named {f!r} in {user}; nothing done")
        print(f"{f}: {c.folder_status(f, [b'MESSAGES'])[b'MESSAGES']} messages")
    if not apply:
        print("dry run; add --apply to move them into", later)
        return
    if not c.folder_exists(later):
        c.create_folder(later)
    c.subscribe_folder(later)
    for f in folders:
        c.select_folder(f)
        uids = c.search(["ALL"])
        for i in range(0, len(uids), BATCH):
            for _attempt in range(3):
                try:
                    c.move(uids[i:i + BATCH], later)
                    break
                except Exception as e:
                    print(f"  retry {f} batch {i}: {e}")
                    time.sleep(10)
                    c = connect()
                    c.select_folder(f)
            else:
                raise SystemExit(f"giving up on {f}; nothing deleted")
        c.unselect_folder()
        left = c.folder_status(f, [b"MESSAGES"])[b"MESSAGES"]
        if left == 0:
            c.delete_folder(f)
            print(f"  {f}: moved {len(uids)} to {later}, folder deleted")
        else:
            print(f"  {f}: {left} still inside after the move, folder KEPT")
    c.logout()


if __name__ == "__main__":
    main(sys.argv[1:])
