import hashlib
import json
import pathlib
import sys
import tarfile

archive, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
target.mkdir(parents=True, exist_ok=True)
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    allowed = {"database.dump", "uploads.tar.gz", "manifest.json"}
    if {m.name for m in members} != allowed or any(not m.isfile() for m in members):
        raise SystemExit("Backup archive has an unexpected structure; refusing to restore")
    for member in members:
        stream = tf.extractfile(member)
        if stream is None:
            raise SystemExit("Invalid archive member")
        (target / member.name).write_bytes(stream.read())
manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
if set(manifest.get("sha256", {})) != {"database.dump", "uploads.tar.gz"}:
    raise SystemExit("Backup manifest is invalid; refusing to restore")
for name, expected in manifest["sha256"].items():
    if hashlib.sha256((target / name).read_bytes()).hexdigest() != expected:
        raise SystemExit(f"Checksum failed for {name}; refusing to restore")
uploads = target / "uploads"
uploads.mkdir(exist_ok=True)
with tarfile.open(target / "uploads.tar.gz", "r:gz") as tf:
    for member in tf.getmembers():
        p = pathlib.PurePosixPath(member.name)
        if p.is_absolute() or ".." in p.parts or not (member.isfile() or member.isdir()):
            raise SystemExit("Unsafe upload archive; refusing to restore")
    tf.extractall(uploads)
