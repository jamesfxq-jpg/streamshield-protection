#!/usr/bin/env python3
"""Build the public StreamShield static site and generate the current Windows beta ZIP."""
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "public"

subprocess.run([sys.executable, str(ROOT / "tools" / "package_release.py")], cwd=ROOT, check=True)

if OUT.exists():
    shutil.rmtree(OUT)
OUT.mkdir()

for name in [
    "index.html",
    "privacy.html",
    "terms.html",
    "verify.html",
    "verification-result.html",
    "beta.html",
    "beta-thanks.html",
    "mods.html",
    "release.json",
]:
    src = ROOT / name
    if src.exists():
        shutil.copy2(src, OUT / name)

shutil.copytree(ROOT / "assets", OUT / "assets")
shutil.copytree(ROOT / "releases", OUT / "releases")

print(f"Built public site in {OUT}")
