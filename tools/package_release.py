#!/usr/bin/env python3
"""Package the checked-in Windows distribution and update public release metadata."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = ROOT / "desktop"
VERSION = json.loads((DESKTOP / "app/package.json").read_text())["version"]
FILENAME = f"StreamShield-Protection-{VERSION}-Windows.zip"
RELEASE = ROOT / "releases" / FILENAME
PUBLIC_ORIGIN = "https://streamshield-protection-public.vercel.app"

files = sorted(path for path in DESKTOP.rglob("*") if path.is_file())
assert files and (DESKTOP / "Install StreamShield.cmd").is_file()
assert all("data" not in path.relative_to(DESKTOP).parts for path in files), "Never package local runtime data"
RELEASE.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(RELEASE, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in files:
        entry = zipfile.ZipInfo(path.relative_to(DESKTOP).as_posix(), (2026, 10, 6, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.external_attr = 0o100644 << 16
        archive.writestr(entry, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

with zipfile.ZipFile(RELEASE) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist()) == len(files)

payload = RELEASE.read_bytes()
digest = hashlib.sha256(payload).hexdigest()
metadata = {
    "version": VERSION,
    "channel": "beta",
    "filename": FILENAME,
    "download_url": f"{PUBLIC_ORIGIN}/releases/{FILENAME}",
    "sha256": digest,
    "size_bytes": len(payload),
    "published_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    "notes": "Adds streamer-selected remote moderator access with a restricted Mod Dashboard and Compact Pop-Out, ready-to-paste verification messages, and hash-only network identity: full viewer IPs are not stored or shown.",
}
(ROOT / "release.json").write_text(json.dumps(metadata, indent=2) + "\n")
RELEASE.with_suffix(RELEASE.suffix + ".sha256").write_text(f"{digest}  {FILENAME}\n")
index = ROOT / "index.html"
content, replacements = re.subn(r'(id="release-sha256">)[^<]+', lambda match: match[1] + digest, index.read_text())
assert replacements == 1, "The landing page must have exactly one release checksum"
index.write_text(content)
print(json.dumps({"file": str(RELEASE), "files": len(files), "bytes": len(payload), "sha256": digest}))
