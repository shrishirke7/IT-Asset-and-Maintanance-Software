import fcntl
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/backups"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/app/uploads"))
DATABASE_URL = os.environ["DATABASE_URL"]
RETENTION = {"daily": 14, "weekly": 8, "monthly": 24}

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def create_backup(kind="manual"):
    if kind not in ("daily", "weekly", "monthly", "manual"):
        raise ValueError("Backup type must be daily, weekly, monthly, or manual")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    target = BACKUP_DIR / f"northstar-{kind}-{stamp}.tar.gz"
    with (BACKUP_DIR / ".backup.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix="northstar-backup-") as temp:
            work = Path(temp)
            db_dump, uploads_tar = work / "database.dump", work / "uploads.tar.gz"
            subprocess.run(["pg_dump", "--format=custom", "--dbname", DATABASE_URL, "--file", str(db_dump)], check=True, timeout=900)
            with tarfile.open(uploads_tar, "w:gz") as tf:
                if UPLOAD_DIR.exists():
                    for child in UPLOAD_DIR.iterdir():
                        tf.add(child, arcname=child.name, recursive=True)
            manifest = {"format":1,"created_utc":datetime.now(timezone.utc).isoformat(),"backup_type":kind,"database_file":"database.dump","uploads_file":"uploads.tar.gz","sha256":{"database.dump":sha256(db_dump),"uploads.tar.gz":sha256(uploads_tar)}}
            manifest_path = work / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            staging = BACKUP_DIR / f".{target.name}.partial"
            with tarfile.open(staging, "w:gz") as tf:
                tf.add(db_dump, arcname="database.dump")
                tf.add(uploads_tar, arcname="uploads.tar.gz")
                tf.add(manifest_path, arcname="manifest.json")
            os.replace(staging, target)
            target.chmod(0o600)
        retain = RETENTION.get(kind)
        if retain:
            old = sorted(BACKUP_DIR.glob(f"northstar-{kind}-*.tar.gz"), key=lambda p:p.stat().st_mtime, reverse=True)
            for path in old[retain:]: path.unlink(missing_ok=True)
    return target

if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv) > 1 else "manual"
    print(create_backup(kind).name)
