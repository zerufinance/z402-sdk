#!/usr/bin/env python3
"""Build every release artifact and check what is inside it.

Builds the Python wheel and sdist (python -m build), runs `twine check` on them, builds
the TypeScript package and packs it (npm pack). Then it opens each artifact and FAILS if:

  - a file is not on the allow-list for that artifact, or an allow-listed file is missing
  - a file name is .env or .env.*, or a file refers to a .env file
  - a file holds an IPv4 address other than 127.0.0.1
  - a file holds "home/elite"
  - a file holds an http:// URL to a host other than localhost, 127.0.0.1 or [::1]
    (LICENSE files may hold the Apache license's own http://www.apache.org links)
  - a file holds the word "placeholder"
  - the Python and npm package versions differ (or differ from --expect-version)

Usage (from anywhere):  python scripts/release_check.py [--out DIR] [--expect-version X.Y.Z]
Needs: Python with `build` and `twine` installed; Node 20+ with npm, and `npm ci` done in typescript/.
Exit code 0 only when every check passes.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_DIR = ROOT / "python"
TS_DIR = ROOT / "typescript"

PY_MODULES = ["__init__.py", "check.py", "errors.py", "guard.py", "py.typed", "seller.py"]

LOCAL_HTTP_HOSTS = {"localhost", "127.0.0.1", "[::1]"}
LICENSE_HTTP_HOSTS = {"www.apache.org"}
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
HTTP_URL = re.compile(r"http://([^\s/\"'<>()`]*)", re.IGNORECASE)
DOTENV_REF = re.compile(r"(?:^|[\s\"'/=])\.env(?:\.[\w-]+)?(?=[\s\"'`]|$)", re.MULTILINE)
WORDS = [("home/elite", re.compile(r"home/elite", re.IGNORECASE)),
         ("placeholder", re.compile(r"placeholder", re.IGNORECASE))]


def allowed_files(version: str) -> dict[str, set[str]]:
    dist_info = f"zeru_z402-{version}.dist-info"
    sdist = f"zeru_z402-{version}"
    egg = f"{sdist}/src/zeru_z402.egg-info"
    return {
        "wheel": {f"z402/{m}" for m in PY_MODULES}
        | {f"{dist_info}/{n}" for n in ("METADATA", "WHEEL", "RECORD", "top_level.txt", "licenses/LICENSE")},
        "sdist": {f"{sdist}/src/z402/{m}" for m in PY_MODULES}
        | {f"{sdist}/{n}" for n in ("PKG-INFO", "pyproject.toml", "setup.cfg", "README.md", "LICENSE", "MANIFEST.in")}
        | {f"{egg}/{n}" for n in ("PKG-INFO", "SOURCES.txt", "dependency_links.txt", "requires.txt", "top_level.txt")},
        "npm": {f"package/{n}" for n in ("package.json", "README.md", "LICENSE", "dist/index.js", "dist/index.d.ts")},
    }


def run(cmd: list[str], cwd: Path) -> str:
    print("$ " + " ".join(cmd), flush=True)
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.stdout.write(p.stdout[-4000:])
        sys.stderr.write(p.stderr[-4000:])
        raise SystemExit(f"FAIL: command exited {p.returncode}: {' '.join(cmd)}")
    return p.stdout


def read_wheel(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist() if not n.endswith("/")}


def read_tar(path: Path) -> dict[str, bytes]:
    out = {}
    with tarfile.open(path, "r:gz") as t:
        for m in t.getmembers():
            if m.isfile():
                out[m.name] = t.extractfile(m).read()
            elif not m.isdir():
                out[m.name] = b""   # links and other members: listed so the allow-list sees them
    return out


def scan_text(name: str, text: str) -> list[str]:
    problems = []
    base = name.rsplit("/", 1)[-1]
    for m in IPV4.finditer(text):
        ip = m.group(0)
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue                      # not an address (an octet over 255)
        if ip != "127.0.0.1":
            problems.append(f"IPv4 address {ip}")
    for m in HTTP_URL.finditer(text):
        hostport = m.group(1)
        if not hostport:
            continue                      # prose such as "plain http:// is refused"
        host = hostport.lower()
        if "@" in host:
            problems.append(f"http:// URL with user info: http://{hostport}")
            continue
        host = host if host.startswith("[") else host.split(":", 1)[0]
        if host.startswith("["):
            host = host[: host.index("]") + 1] if "]" in host else host
        if host in LOCAL_HTTP_HOSTS:
            continue
        if base.startswith("LICENSE") and host in LICENSE_HTTP_HOSTS:
            continue
        problems.append(f"http:// URL to a non-local host: http://{hostport}")
    for label, rx in WORDS:
        if rx.search(text):
            problems.append(f'contains "{label}"')
    if DOTENV_REF.search(text):
        problems.append("refers to a .env file")
    return problems


def check_artifact(kind: str, path: Path, files: dict[str, bytes], allow: set[str]) -> list[str]:
    errors = []
    names = set(files)
    for extra in sorted(names - allow):
        errors.append(f"{kind}: file not on the allow-list: {extra}")
    for missing in sorted(allow - names):
        errors.append(f"{kind}: expected file is missing: {missing}")
    for name, data in sorted(files.items()):
        parts = name.split("/")
        if any(p == ".env" or p.startswith(".env.") for p in parts):
            errors.append(f"{kind}: .env file in the artifact: {name}")
        text = data.decode("utf-8", errors="replace")
        errors += [f"{kind}: {name}: {p}" for p in scan_text(name, text)]
    print(f"  {kind:5} {path.name}: {len(files)} files, {sum(map(len, files.values()))} bytes, "
          f"{'ok' if not errors else f'{len(errors)} problem(s)'}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, help="where to put the artifacts (default: a temporary folder)")
    ap.add_argument("--expect-version", help="fail unless both packages have this version (e.g. from a git tag)")
    args = ap.parse_args()

    m = re.search(r'^version\s*=\s*"([^"]+)"', (PY_DIR / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    py_version = m.group(1) if m else "?"
    ts_version = json.loads((TS_DIR / "package.json").read_text(encoding="utf-8"))["version"]
    errors = []
    if py_version != ts_version:
        errors.append(f"version mismatch: python {py_version}, npm {ts_version}")
    if args.expect_version and args.expect_version != py_version:
        errors.append(f"version mismatch: expected {args.expect_version}, python {py_version}")
    if args.expect_version and args.expect_version != ts_version:
        errors.append(f"version mismatch: expected {args.expect_version}, npm {ts_version}")
    print(f"versions: python {py_version}, npm {ts_version}")

    out = args.out or Path(tempfile.mkdtemp(prefix="z402-release-"))
    out = out.resolve()
    py_out, npm_out = out / "python", out / "npm"
    for d in (py_out, npm_out):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)

    run([sys.executable, "-m", "build", "--outdir", str(py_out), "."], PY_DIR)
    for leftover in (PY_DIR / "build", *PY_DIR.glob("src/*.egg-info")):
        shutil.rmtree(leftover, ignore_errors=True)
    wheels, sdists = sorted(py_out.glob("*.whl")), sorted(py_out.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit(f"FAIL: expected one wheel and one sdist in {py_out}")
    print(run([sys.executable, "-m", "twine", "check", "--strict", str(wheels[0]), str(sdists[0])], PY_DIR).strip())

    npm = shutil.which("npm")
    if not npm:
        raise SystemExit("FAIL: npm not found")
    run([npm, "run", "build"], TS_DIR)
    packed = json.loads(run([npm, "pack", "--json", "--pack-destination", str(npm_out)], TS_DIR))
    tgz = npm_out / packed[0]["filename"]

    allow = allowed_files(py_version)
    print("artifacts:")
    errors += check_artifact("wheel", wheels[0], read_wheel(wheels[0]), allow["wheel"])
    errors += check_artifact("sdist", sdists[0], read_tar(sdists[0]), allow["sdist"])
    errors += check_artifact("npm", tgz, read_tar(tgz), allow["npm"])

    if errors:
        print("\nRELEASE CHECK FAILED:")
        for e in errors:
            print("  - " + e)
        return 1
    print(f"\nRELEASE CHECK PASSED: 3 artifacts in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
