#!/usr/bin/env python3
"""Download the selected LogHub-2k datasets from the official LogPAI repository."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent.parent
BASE_URL = (
    "https://raw.githubusercontent.com/logpai/logparser/main/data/loghub_2k"
)
BLOCK_SIZE = 64 * 1024
DOWNLOADS = (
    ("OpenSSH/OpenSSH_2k.log", "raw"),
    ("OpenSSH/OpenSSH_2k.log_structured.csv", "reference"),
    ("OpenSSH/OpenSSH_2k.log_templates.csv", "reference"),
    ("Linux/Linux_2k.log", "raw"),
    ("Linux/Linux_2k.log_structured.csv", "reference"),
    ("Linux/Linux_2k.log_templates.csv", "reference"),
    ("Apache/Apache_2k.log", "raw"),
    ("Apache/Apache_2k.log_structured.csv", "reference"),
    ("Apache/Apache_2k.log_templates.csv", "reference"),
)
LICENSE = ("LICENSE", "data")


def looks_like_html(prefix: bytes, content_type: str) -> bool:
    """Reject common HTML error responses before promoting a download."""
    if "text/html" in content_type.lower():
        return True
    beginning = prefix.lstrip().lower()
    return beginning.startswith((b"<!doctype html", b"<html", b"<head"))


def download_one(relative_source: str, destination: Path) -> str:
    """Fetch one source to a temporary file and atomically keep verified bytes."""
    source_url = f"{BASE_URL}/{relative_source}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = Request(source_url, headers={"User-Agent": "LogGuardAI-dataset-fetch/1.0"})
    temporary_path: Path | None = None

    try:
        with urlopen(request, timeout=45) as response:
            expected_length = response.headers.get("Content-Length")
            content_type = response.headers.get("Content-Type", "")
            digest = hashlib.sha256()
            received = 0
            prefix = bytearray()

            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{destination.name}.",
                suffix=".part",
                dir=destination.parent,
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                while True:
                    chunk = response.read(BLOCK_SIZE)
                    if not chunk:
                        break
                    if len(prefix) < 512:
                        prefix.extend(chunk[: 512 - len(prefix)])
                    temporary.write(chunk)
                    digest.update(chunk)
                    received += len(chunk)
                    expected_display = expected_length or "?"
                    print(
                        f"\r  {destination.name}: {received:,}/{expected_display} bytes",
                        end="",
                        flush=True,
                    )

            print()
            if received == 0:
                raise ValueError("the server returned an empty file")
            if expected_length is not None and received != int(expected_length):
                raise ValueError(
                    f"incomplete response ({received} of {expected_length} bytes)"
                )
            if looks_like_html(bytes(prefix), content_type):
                raise ValueError("the server returned an HTML page instead of data")

            if destination.is_file() and destination.stat().st_size == received:
                existing_digest = hashlib.sha256()
                with destination.open("rb") as existing:
                    for chunk in iter(lambda: existing.read(BLOCK_SIZE), b""):
                        existing_digest.update(chunk)
                if existing_digest.digest() == digest.digest():
                    temporary_path.unlink()
                    temporary_path = None
                    return "verified existing"

            os.replace(temporary_path, destination)
            temporary_path = None
            return "downloaded"
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    jobs = [
        (name, ROOT / "data" / category / name)
        for name, category in DOWNLOADS
    ]
    jobs.append((LICENSE[0], ROOT / LICENSE[1] / LICENSE[0]))
    failures: list[str] = []

    for source_path, destination in jobs:
        print(f"{source_path}")
        try:
            status = download_one(source_path, destination)
            print(f"  {status}: {destination.relative_to(ROOT)}")
        except (HTTPError, URLError, OSError, ValueError) as error:
            failures.append(f"{source_path}: {error}")
            print(f"  ERROR: {error}", file=sys.stderr)

    if failures:
        print(f"\nDownload failed for {len(failures)} file(s):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"\nSuccessfully verified {len(jobs)} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
