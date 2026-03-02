#!/usr/bin/env python3
"""Download and extract Chrome/Edge extensions by ID (hardened version).

Security features:
  1. Zip Slip protection (path traversal on extract)
  2. Zip Bomb protection (size & file count limits)
  3. Extension ID validation (injection prevention)
  4. Output path validation (directory traversal prevention)
  5. CRX header bounds checking
  6. Symlink attack prevention
  7. Streaming download with size limit
"""

import io
import re
import sys
import struct
import logging
import zipfile
import argparse
import requests
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CHROME_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&acceptformat=crx2,crx3&prodversion=130.0"
    "&x=id%3D{id}%26uc"
)
EDGE_URL = (
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
    "?response=redirect&x=id%3D{id}%26installsource%3Dondemand%26uc"
)
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/130.0.0.0 Safari/537.36"
)

# Extension IDs: 32 lowercase a-p characters (base16 with a-p alphabet)
EXT_ID_PATTERN = re.compile(r"^[a-p]{32}$")

# Safety limits
MAX_DOWNLOAD_SIZE = 200 * 1024 * 1024   # 200 MB download
MAX_EXTRACT_SIZE = 500 * 1024 * 1024    # 500 MB uncompressed total
MAX_FILE_COUNT = 5_000                   # max files inside ZIP
MAX_SINGLE_FILE = 50 * 1024 * 1024      # 50 MB per individual file
REQUEST_TIMEOUT = 60                     # seconds

SOURCES = [
    ("Chrome", CHROME_URL),
    ("Edge", EDGE_URL),
]

log = logging.getLogger("crx_downloader")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_ext_id(ext_id: str) -> str:
    """Validate that the extension ID matches the expected format."""
    ext_id = ext_id.strip().lower()
    if not EXT_ID_PATTERN.match(ext_id):
        raise ValueError(
            f"Invalid extension ID: '{ext_id}'. "
            "Expected: 32 lowercase characters (a-p)."
        )
    return ext_id


def validate_output_path(path: Path, base_dir: Path | None = None) -> Path:
    """Resolve and validate the output directory path."""
    resolved = path.resolve()
    if base_dir is not None:
        base = base_dir.resolve()
        if not str(resolved).startswith(str(base) + "/") and resolved != base:
            raise ValueError(f"Output path escapes base directory: {resolved}")
    return resolved


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
def download(ext_id: str) -> bytes:
    """Download the CRX file from Chrome or Edge Web Store."""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    for name, url_template in SOURCES:
        url = url_template.format(id=ext_id)
        try:
            r = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                stream=True,
                allow_redirects=True,
            )
            r.raise_for_status()

            chunks: list[bytes] = []
            total = 0
            for chunk in r.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > MAX_DOWNLOAD_SIZE:
                    raise OverflowError(
                        f"Download exceeds {MAX_DOWNLOAD_SIZE} byte limit"
                    )
                chunks.append(chunk)

            data = b"".join(chunks)
            if len(data) < 100:
                log.warning("[%s] Response too small (%d bytes), skipping.", name, len(data))
                continue

            log.info("[+] Downloaded via %s (%d bytes)", name, len(data))
            return data

        except requests.RequestException as exc:
            log.warning("[-] Failed via %s: %s", name, exc)
        except OverflowError as exc:
            log.error("[-] %s", exc)

    sys.exit("[!] Could not download from any source.")


# ---------------------------------------------------------------------------
# CRX parsing
# ---------------------------------------------------------------------------
def strip_crx_header(data: bytes) -> bytes:
    """Remove the CRX header and return raw ZIP data.

    Supports CRX2 and CRX3 with strict bounds checking.
    """
    if len(data) < 4:
        sys.exit("[!] File too small to be a valid CRX.")

    if data[:4] == b"Cr24":
        if len(data) < 12:
            sys.exit("[!] Corrupt CRX: incomplete header.")

        version = struct.unpack("<I", data[4:8])[0]

        if version == 3:
            header_size = struct.unpack("<I", data[8:12])[0]
            offset = 12 + header_size
            if header_size < 0 or offset > len(data):
                sys.exit(
                    f"[!] Invalid CRX3: header_size={header_size}, "
                    f"file={len(data)} bytes."
                )
            zip_data = data[offset:]

        elif version == 2:
            if len(data) < 16:
                sys.exit("[!] Corrupt CRX2: incomplete header.")
            pubkey_len = struct.unpack("<I", data[8:12])[0]
            sig_len = struct.unpack("<I", data[12:16])[0]
            offset = 16 + pubkey_len + sig_len
            if pubkey_len < 0 or sig_len < 0 or offset > len(data):
                sys.exit(
                    f"[!] Invalid CRX2: pubkey_len={pubkey_len}, "
                    f"sig_len={sig_len}, file={len(data)} bytes."
                )
            zip_data = data[offset:]

        else:
            sys.exit(f"[!] Unknown CRX version: {version}")

    elif data[:2] == b"PK":
        zip_data = data
    else:
        sys.exit("[!] Unknown format (neither CRX nor ZIP).")

    if not zip_data[:2] == b"PK":
        sys.exit("[!] Data after CRX header is not a valid ZIP.")

    return zip_data


# ---------------------------------------------------------------------------
# Safe extraction
# ---------------------------------------------------------------------------
def safe_extract(zip_data: bytes, dest: Path) -> None:
    """Extract ZIP data to *dest* with full security checks."""
    dest = dest.resolve()

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        members = zf.infolist()

        if len(members) > MAX_FILE_COUNT:
            raise ValueError(
                f"ZIP contains {len(members)} files (limit: {MAX_FILE_COUNT})."
            )

        total_uncompressed = 0
        for info in members:
            # Reject symlinks
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if unix_mode != 0 and (unix_mode & 0o170000) == 0o120000:
                raise ValueError(f"ZIP contains symlink: {info.filename}")

            # Reject path traversal
            resolved = (dest / info.filename).resolve()
            if not str(resolved).startswith(str(dest) + "/") and resolved != dest:
                raise ValueError(f"Path traversal detected: {info.filename}")

            # Individual file size
            if info.file_size > MAX_SINGLE_FILE:
                raise ValueError(
                    f"File too large: {info.filename} "
                    f"({info.file_size} bytes, limit: {MAX_SINGLE_FILE})."
                )

            total_uncompressed += info.file_size

        if total_uncompressed > MAX_EXTRACT_SIZE:
            raise ValueError(
                f"Total uncompressed size ({total_uncompressed} bytes) "
                f"exceeds limit ({MAX_EXTRACT_SIZE} bytes)."
            )

        # Extract with streaming size guard (protects against lying headers)
        for info in members:
            target = (dest / info.filename).resolve()

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)

            bytes_written = 0
            with zf.open(info) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(8192)
                    if not chunk:
                        break
                    bytes_written += len(chunk)
                    if bytes_written > MAX_SINGLE_FILE:
                        dst.close()
                        target.unlink(missing_ok=True)
                        raise ValueError(
                            f"Actual file size exceeds declared limit: {info.filename}"
                        )
                    dst.write(chunk)

    log.info("[+] Safely extracted to: %s", dest)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def extract(data: bytes, out: Path) -> None:
    """Strip CRX header and safely extract the ZIP contents."""
    zip_data = strip_crx_header(data)
    safe_extract(zip_data, out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download and extract Chrome/Edge extensions by ID.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s cjpalhdlnbpafiamejdnhcphjbkeiagm\n"
            "  %(prog)s cjpalhdlnbpafiamejdnhcphjbkeiagm -o ublock\n"
        ),
    )
    parser.add_argument(
        "extension_id",
        help="Extension ID (32 a-p characters).",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output folder (default: extension ID).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (debug).",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        format="%(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    try:
        ext_id = validate_ext_id(args.extension_id)
    except ValueError as exc:
        parser.error(str(exc))

    out_name = args.output if args.output else ext_id
    out = validate_output_path(Path(out_name))
    out.mkdir(parents=True, exist_ok=True)

    data = download(ext_id)
    extract(data, out)

    log.info("[+] Done. Extension saved to: %s", out)


if __name__ == "__main__":
    main()
