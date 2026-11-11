#!/usr/bin/env python3
"""Verify a firmware release manifest (and optionally its packages).

Used by `.github/workflows/verify-manifest.yml` and runnable by hand. Only needs
`cryptography` (and `lzma`, which is in the standard library).

    python verify_release.py --dir .                  # signature only
    python verify_release.py --dir . --assets ../out  # + hashes and containers
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import lzma
import pathlib
import struct
import sys

CODEC_XZ = 1
CODEC_GZIP = 2
HBFW_INFO = b"HBFW1"


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_pubkeys(path: pathlib.Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"{path} not found")
    if not isinstance(data, dict) or not data:
        fail(f"{path} must be a non-empty object of kid -> base64 key")
    return {str(k): str(v) for k, v in data.items()}


def verify_signature(manifest: bytes, signature: bytes, pub_b64: str, kid: str) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key_bytes = base64.b64decode(pub_b64)
    except Exception as exc:  # noqa: BLE001
        fail(f"pubkey {kid} is not valid base64: {exc}")
    if len(key_bytes) != 32:
        fail(f"pubkey {kid} must be 32 bytes, got {len(key_bytes)}")
    if len(signature) != 64:
        fail(f"signature must be 64 bytes, got {len(signature)}")
    pub = Ed25519PublicKey.from_public_bytes(key_bytes)
    try:
        pub.verify(signature, manifest)
    except InvalidSignature:
        fail(f"manifest signature does not verify with key {kid!r}")
    print(f"signature OK (kid {kid})")


def _hkdf(psk: bytes, nonce: bytes, raw_size: int, blob_size: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    salt = nonce + struct.pack("<I", raw_size) + struct.pack("<I", blob_size)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HBFW_INFO).derive(psk)


def unwrap(container: bytes, psk: str) -> bytes:
    if container[:4] != b"HBFW":
        fail(f"package magic {container[:4]!r} is not HBFW")
    if container[4] != 1:
        fail(f"unsupported HBFW format {container[4]}")
    codec = container[5]
    flags = struct.unpack_from("<H", container, 6)[0]
    raw_size = struct.unpack_from("<I", container, 8)[0]
    blob_size = struct.unpack_from("<I", container, 12)[0]
    body = container[16:]
    if flags & 1:
        nonce, sealed = body[:12], body[12:]
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = _hkdf(psk.encode(), nonce, raw_size, blob_size)
        try:
            blob = AESGCM(key).decrypt(nonce, sealed, None)
        except Exception as exc:  # noqa: BLE001
            fail(f"AEAD tag rejected: {exc}")
    else:
        blob = body
    if len(blob) != blob_size:
        fail(f"payload {len(blob)} != blobSize {blob_size}")
    if codec == CODEC_XZ:
        raw = lzma.decompress(blob, format=lzma.FORMAT_XZ)
    elif codec == CODEC_GZIP:
        raw = gzip.decompress(blob)
    else:
        fail(f"unsupported codec {codec}")
    if len(raw) != raw_size:
        fail(f"raw {len(raw)} != rawSize {raw_size}")
    return raw


def check_asset(entry: dict, assets_dir: pathlib.Path, psk: str, kind: str) -> None:
    pkg_path = assets_dir / entry["pkgFile"]
    if not pkg_path.exists():
        fail(f"{kind}: {pkg_path} is missing")
    pkg = pkg_path.read_bytes()
    if len(pkg) != entry["pkgSize"]:
        fail(f"{kind}: pkgSize {len(pkg)} != {entry['pkgSize']}")
    if sha256_bytes(pkg) != entry["pkgSha256"]:
        fail(f"{kind}: pkgSha256 mismatch")
    raw = unwrap(pkg, psk)
    if len(raw) != entry["rawSize"]:
        fail(f"{kind}: rawSize {len(raw)} != {entry['rawSize']}")
    if sha256_bytes(raw) != entry["sha256"]:
        fail(f"{kind}: raw sha256 mismatch")
    if kind == "app":
        image_id = struct.unpack_from("<H", raw, 196 + 6)[0]
        payload_len = struct.unpack_from("<I", raw, 196 + 12)[0]
        if image_id != 0x2793:
            fail(f"app: image id 0x{image_id:04x} is not 0x2793")
        if 0x400 + payload_len != len(raw):
            fail("app: header length does not match the payload")
        print(f"app OK: imageId 0x{image_id:04x}, raw {len(raw):,} B, pkg {len(pkg):,} B")
    else:
        if raw[:4] != b"WTOC":
            fail("ui: bundle magic is not WTOC")
        version, count, total = struct.unpack_from("<III", raw, 4)
        if total != len(raw):
            fail(f"ui: directory total {total} != {len(raw)}")
        build_id = struct.unpack_from("<I", raw, 16)[0] if version >= 2 else 0
        print(
            f"ui OK: WTOC v{version}, {count} sections, buildId {build_id}, "
            f"raw {len(raw):,} B, pkg {len(pkg):,} B"
        )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".", help="directory holding manifest.json/sig")
    ap.add_argument("--assets", help="directory holding the *.hbfw packages")
    ap.add_argument("--pubkeys", help="defaults to <dir>/pubkeys.json")
    ap.add_argument("--psk", default="honeybox-fw-2026-default-psk")
    args = ap.parse_args(argv)

    d = pathlib.Path(args.dir)
    manifest_path = d / "manifest.json"
    sig_path = d / "manifest.sig"
    if not manifest_path.exists():
        fail(f"{manifest_path} not found")
    if not sig_path.exists():
        fail(f"{sig_path} not found")

    manifest_bytes = manifest_path.read_bytes()
    signature = base64.b64decode(sig_path.read_text(encoding="utf-8").strip())
    doc = json.loads(manifest_bytes.decode("utf-8"))

    kid = (doc.get("sig") or {}).get("kid")
    if not kid:
        fail("manifest has no sig.kid")
    if (doc.get("sig") or {}).get("alg") != "ed25519":
        fail("manifest sig.alg must be 'ed25519'")

    pubkeys = load_pubkeys(pathlib.Path(args.pubkeys) if args.pubkeys else d / "pubkeys.json")
    if kid not in pubkeys:
        fail(f"kid {kid!r} is not listed in pubkeys.json")
    verify_signature(manifest_bytes, signature, pubkeys[kid], kid)

    print(
        f"manifest OK: schema {doc.get('schema')}, seq {doc.get('releaseSeq')}, "
        f"channel {doc.get('channel')}, tag {doc.get('tag')}"
    )

    if args.assets:
        assets = pathlib.Path(args.assets)
        for kind in ("app", "ui"):
            entry = doc.get(kind)
            if entry:
                check_asset(entry, assets, args.psk, kind)

    print("VERIFY OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
