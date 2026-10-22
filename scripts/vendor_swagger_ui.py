"""Vendor an exact swagger-ui-dist release into rlapi's static directory.

    uv run python scripts/vendor_swagger_ui.py 5.33.2

Takes an exact version, never a range: the point of vendoring (THREAT_MODEL.md
F-14) is that the script the docs page runs changes only in a commit.

The tarball is checked against the registry's own `dist.integrity` (SHA-512)
before anything is extracted. Know what that does and does not buy: it catches
a corrupted or substituted download, but the hash comes from the same registry
as the tarball, so it cannot catch a malicious *publish*. That is the job of
choosing the version deliberately and reviewing the diff.

Writes `SHA256SUMS` beside the files. `tests/attacks/test_docs_supply_chain.py`
checks the vendored bytes against it, so a later hand-edit -- including one by a
pre-commit fixer -- fails the suite instead of shipping.
"""

import base64
import hashlib
import io
import re
import sys
import tarfile
from pathlib import Path

import httpx

REGISTRY = "https://registry.npmjs.org/swagger-ui-dist"
ABBREVIATED = "application/vnd.npm.install-v1+json"
DEST = Path(__file__).resolve().parents[1] / "packages/rlapi/src/rlapi/static/swagger-ui"
#: What the docs page loads, plus the licence and notices that permit redistributing it.
FILES = (
    "swagger-ui-bundle.js",
    "swagger-ui.css",
    "favicon-32x32.png",
    "LICENSE",
    "NOTICE",
    "swagger-ui-bundle.js.LICENSE.txt",  # notices of the libraries bundled inside
)


def main(version: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        sys.exit(f"exact version required, got {version!r}")

    with httpx.Client(timeout=30, follow_redirects=False) as http:
        # The abbreviated packument, as npm itself requests it. The per-version
        # endpoint (`/swagger-ui-dist/5.33.2`) answered 503 after two minutes on
        # 2026-10-21 while this one answered in 0.1s.
        packument = http.get(REGISTRY, headers={"Accept": ABBREVIATED}).raise_for_status()
        meta = packument.json()["versions"].get(version)
        if meta is None:
            sys.exit(f"swagger-ui-dist {version} is not on the registry")
        integrity: str = meta["dist"]["integrity"]
        tarball = http.get(meta["dist"]["tarball"]).raise_for_status().content

    algorithm, _, expected = integrity.partition("-")
    if algorithm != "sha512":
        sys.exit(f"unexpected integrity algorithm {algorithm!r}")
    if base64.b64encode(hashlib.sha512(tarball).digest()).decode() != expected:
        sys.exit("tarball does not match the registry's dist.integrity -- refusing")

    DEST.mkdir(parents=True, exist_ok=True)
    sums = []
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        for name in FILES:
            member = tar.extractfile(f"package/{name}")
            if member is None:
                sys.exit(f"{name} missing from the tarball")
            data = member.read()
            (DEST / name).write_bytes(data)
            sums.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
    (DEST / "SHA256SUMS").write_text("".join(sums))
    (DEST / "VERSION").write_text(f"{version}\n")
    sys.stdout.write(f"swagger-ui-dist {version} -> {DEST}\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
