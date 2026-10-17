import hashlib
import json
import pathlib
import sys
import tarfile

archive, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
target.mkdir(parents=True, exist_ok=True)

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    allowed = {"database.dump", "uploads.tar.gz", "manifest.json"}
    if len(members) != len(allowed) or {m.name for m in members} != allowed or any(not m.isfile() for m in members):
        raise SystemExit("Backup archive has an unexpected structure; refusing to restore")
    for member in members:
        if member.size < 0 or member.size > 1024 * 1024 * 1024 or (member.name == "manifest.json" and member.size > 1024 * 1024):
            raise SystemExit("Backup archive member exceeds the allowed size; refusing to restore")
        stream = tf.extractfile(member)
        if stream is None:
            raise SystemExit("Invalid archive member")
        with (target / member.name).open("wb") as output:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                output.write(block)
manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
if set(manifest.get("sha256", {})) != {"database.dump", "uploads.tar.gz"}:
    raise SystemExit("Backup manifest is invalid; refusing to restore")
for name, expected in manifest["sha256"].items():
    if sha256(target / name) != expected:
        raise SystemExit(f"Checksum failed for {name}; refusing to restore")
uploads = target / "uploads"
uploads.mkdir(exist_ok=True)
with tarfile.open(target / "uploads.tar.gz", "r:gz") as tf:
    members = tf.getmembers()
    if sum(member.size for member in members) > 8 * 1024 * 1024 * 1024:
        raise SystemExit("Upload archive expands beyond the allowed size; refusing to restore")
    for member in members:
        p = pathlib.PurePosixPath(member.name)
        if member.size < 0 or p.is_absolute() or ".." in p.parts or not (member.isfile() or member.isdir()):
            raise SystemExit("Unsafe upload archive; refusing to restore")
    tf.extractall(uploads)
