#!/usr/bin/env python3
"""
nous-update — Knowledge pack downloader and bundler
Downloads security intelligence and operational signatures for offline airgap transfer
"""

import argparse
import hashlib
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import urllib.error
import zipfile
from datetime import datetime, timedelta
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Source Registry — loaded from sources.yaml at startup
# ────────────────────────────────────────────────────────────────────────────

SOURCES = {}  # populated by _load_sources() in main()


def _load_sources(sources_file: str) -> dict:
    """Load intel source catalog from sources.yaml, returning flat SOURCES dict."""
    try:
        import yaml
    except ImportError:
        logger.error("pyyaml is required: pip install pyyaml")
        sys.exit(1)
    with open(sources_file, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    sources = {}
    for category, packs in data.items():
        if not isinstance(packs, dict):
            continue
        for name, pack in packs.items():
            if not isinstance(pack, dict):
                continue
            entry = dict(pack)
            entry["category"] = category
            # Interpolate {version} into URL template if present
            if "version" in entry and "{version}" in entry.get("url", ""):
                entry["url"] = entry["url"].replace("{version}", entry["version"])
            sources[name] = entry
    return sources


# ────────────────────────────────────────────────────────────────────────────
# Utilities
# ────────────────────────────────────────────────────────────────────────────

def _get_github_token() -> str:
    """Return GitHub token if set, for rate limit bypass."""
    return os.getenv("GITHUB_TOKEN", "").strip()


def _make_request(url: str, timeout: int = 30) -> bytes:
    """Fetch URL content with GitHub token if available."""
    headers = {}
    token = _get_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            # Check rate limit
            remaining = response.headers.get("X-RateLimit-Remaining", "")
            if remaining and int(remaining) < 10:
                logger.warning(f"GitHub rate limit approaching: {remaining} requests remaining")

            return response.read()
    except urllib.error.HTTPError as e:
        if e.code == 429:
            reset_time = e.headers.get("X-RateLimit-Reset", "")
            logger.warning(f"GitHub rate limit exhausted. Reset at: {reset_time}")
        raise


def _sha256_file(path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return f"sha256:{sha256_hash.hexdigest()}"


def _sha256_dir(path: Path) -> str:
    """Calculate SHA256 hash of a directory (hashing all files in sorted order)."""
    sha256_hash = hashlib.sha256()
    for fpath in sorted(path.rglob("*")):
        if fpath.is_file():
            with open(fpath, "rb") as f:
                sha256_hash.update(f.read())
    return f"sha256:{sha256_hash.hexdigest()}"


def _substitute_date_placeholders(url: str) -> str:
    """Replace {90_days_ago} with ISO 8601 date."""
    ninety_days_ago = (datetime.utcnow() - timedelta(days=90)).date()
    return url.replace("{90_days_ago}", ninety_days_ago.isoformat())


# ────────────────────────────────────────────────────────────────────────────
# Download handlers
# ────────────────────────────────────────────────────────────────────────────

def _download_file(pack_name: str, source: dict, rules_dir: Path) -> dict:
    """Download a single file source."""
    url = _substitute_date_placeholders(source["url"])
    dest_path = rules_dir / source["dest"]
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"[{pack_name}] Downloading file...")
    data = _make_request(url)

    with open(dest_path, "wb") as f:
        f.write(data)

    checksum = _sha256_file(dest_path)
    return {"path": str(dest_path), "checksum": checksum}


def _download_zip(pack_name: str, source: dict, rules_dir: Path) -> dict:
    """Download and extract a zip file source."""
    url = source["url"]
    dest_dir = rules_dir / source["dest"]
    subpath = source.get("subpath")

    logger.info(f"[{pack_name}] Downloading zip...")
    data = _make_request(url)

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = Path(tmpdir) / "archive.zip"
        with open(zip_path, "wb") as f:
            f.write(data)

        # Extract zip
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmpdir)

        # Handle subpath
        if subpath:
            extract_dir = Path(tmpdir) / subpath
            if not extract_dir.exists():
                raise ValueError(f"Subpath {subpath} not found in archive")
        else:
            # Find the only top-level directory in the archive
            contents = list(Path(tmpdir).iterdir())
            contents = [c for c in contents if c.name != "archive.zip"]
            if len(contents) == 1 and contents[0].is_dir():
                extract_dir = contents[0]
            else:
                extract_dir = Path(tmpdir)

        # Copy to destination
        dest_dir.parent.mkdir(parents=True, exist_ok=True)
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        shutil.copytree(extract_dir, dest_dir)

    checksum = _sha256_dir(dest_dir)
    return {"path": str(dest_dir), "checksum": checksum}


def _download_targz(pack_name: str, source: dict, rules_dir: Path) -> dict:
    """Download and extract a tar.gz file source."""
    url = source["url"]
    dest_dir = rules_dir / source["dest"]
    subpath = source.get("subpath")

    logger.info(f"[{pack_name}] Downloading tar.gz...")
    data = _make_request(url)

    with tempfile.TemporaryDirectory() as tmpdir:
        tar_path = Path(tmpdir) / "archive.tar.gz"
        with open(tar_path, "wb") as f:
            f.write(data)

        # Extract tar.gz
        with tarfile.open(tar_path, "r:gz") as tf:
            tf.extractall(tmpdir)

        # Handle subpath
        if subpath:
            extract_dir = Path(tmpdir) / subpath
            if not extract_dir.exists():
                raise ValueError(f"Subpath {subpath} not found in archive")
        else:
            # Find the only top-level directory
            contents = list(Path(tmpdir).iterdir())
            contents = [c for c in contents if c.name != "archive.tar.gz"]
            if len(contents) == 1 and contents[0].is_dir():
                extract_dir = contents[0]
            else:
                extract_dir = Path(tmpdir)

        # Copy to destination
        dest_dir.parent.mkdir(parents=True, exist_ok=True)
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        shutil.copytree(extract_dir, dest_dir)

    checksum = _sha256_dir(dest_dir)
    return {"path": str(dest_dir), "checksum": checksum}


def _download_pack(pack_name: str, source: dict, rules_dir: Path) -> dict:
    """Download a single pack and return metadata for manifest."""
    try:
        download_type = source.get("type", "file")

        if download_type == "file":
            result = _download_file(pack_name, source, rules_dir)
        elif download_type == "zip":
            result = _download_zip(pack_name, source, rules_dir)
        elif download_type == "targz":
            result = _download_targz(pack_name, source, rules_dir)
        else:
            raise ValueError(f"Unknown download type: {download_type}")

        logger.info(f"[{pack_name}] OK")
        return result

    except Exception as e:
        logger.warning(f"[{pack_name}] failed: {e}")
        return None


# ────────────────────────────────────────────────────────────────────────────
# Manifest generation
# ────────────────────────────────────────────────────────────────────────────

def _build_manifest(enabled_packs: dict, rules_dir: Path) -> dict:
    """Build manifest.json per SPEC.md schema."""
    now = datetime.utcnow()
    manifest = {
        "version": now.strftime("%Y-%m"),
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "security": {},
        "operations": {},
        "files": {},
    }

    for pack_name, result in enabled_packs.items():
        if result is None:
            continue

        source = SOURCES[pack_name]
        category = source["category"]

        # Add to category metadata
        pack_meta = {}
        # Try to extract version/commit info from URL (simplified)
        if "github.com" in source["url"]:
            if "/releases/latest/download/" in source["url"]:
                pack_meta["release"] = "latest"
            else:
                pack_meta["commit"] = "unknown"

        manifest[category][pack_name] = pack_meta

        # Add file checksum
        dest_rel = source["dest"]
        if result.get("checksum"):
            manifest["files"][dest_rel] = result["checksum"]

    return manifest


# ────────────────────────────────────────────────────────────────────────────
# Post-processing: derived indexes from downloaded packs
# ────────────────────────────────────────────────────────────────────────────

def _build_sigma_attack_index(rules_dir: Path) -> Path | None:
    """Scan downloaded Sigma YAML files and emit cti/sigma-attack-index.json.

    Maps Sigma rule UUID → list of ATT&CK technique IDs (T1234, T1234.001).
    The assembler uses this index to enrich happenings with ATT&CK context
    without needing to re-parse Sigma rule files at runtime.

    Requires pyyaml (already installed in intel-updater image).
    """
    try:
        import re
        import yaml
    except ImportError:
        logger.warning("pyyaml not available — skipping sigma-attack-index generation")
        return None

    sigma_dir = rules_dir / "sigma"
    if not sigma_dir.exists():
        logger.info("No sigma/ directory found — skipping sigma-attack-index")
        return None

    attack_tag_re = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
    index: dict[str, list[str]] = {}

    yaml_files = list(sigma_dir.rglob("*.yaml")) + list(sigma_dir.rglob("*.yml"))
    for path in yaml_files:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for doc in yaml.safe_load_all(f):
                    if not doc or not isinstance(doc, dict):
                        continue
                    rule_id = doc.get("id")
                    if not rule_id:
                        continue
                    tech_ids = []
                    for tag in (doc.get("tags") or []):
                        m = attack_tag_re.match(str(tag))
                        if m:
                            tech_ids.append(m.group(1).upper())
                    if tech_ids:
                        index[str(rule_id)] = list(dict.fromkeys(tech_ids))
        except Exception:
            continue

    out_path = rules_dir / "cti" / "sigma-attack-index.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(index, f, separators=(",", ":"))

    logger.info(f"sigma-attack-index: {len(index)} rules with ATT&CK mappings → {out_path}")
    return out_path


# ────────────────────────────────────────────────────────────────────────────
# CLI modes
# ────────────────────────────────────────────────────────────────────────────

def cmd_list_packs(args):
    """List all available packs."""
    for pack_name, source in sorted(SOURCES.items()):
        category = source["category"]
        description = source["description"]
        print(f"{pack_name:30} [{category:11}] {description}")


def _filter_packs(pack_filter: str) -> dict:
    """Filter packs by name or category."""
    if not pack_filter:
        return SOURCES

    names = set()
    for item in pack_filter.split(","):
        item = item.strip()
        if item in ("security", "operations"):
            # Category filter
            names.update(
                name for name, source in SOURCES.items()
                if source["category"] == item
            )
        elif item in SOURCES:
            # Individual pack
            names.add(item)
        else:
            logger.warning(f"Unknown pack: {item}")

    return {k: v for k, v in SOURCES.items() if k in names}


def cmd_online(args):
    """Download packs to rules_dir."""
    rules_dir = Path(args.rules_dir)
    rules_dir.mkdir(parents=True, exist_ok=True)

    enabled_packs = _filter_packs(args.packs)
    results = {}

    for pack_name, source in enabled_packs.items():
        result = _download_pack(pack_name, source, rules_dir)
        results[pack_name] = result

    # Build derived indexes from downloaded packs
    _build_sigma_attack_index(rules_dir)

    # Write manifest
    manifest = _build_manifest(results, rules_dir)
    manifest_path = rules_dir / "intel-manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Manifest written: {manifest_path}")

    # Print summary
    _print_summary(results)


def cmd_bundle(args):
    """Download packs and create dated bundle zip."""
    rules_dir = Path(args.rules_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    rules_dir.mkdir(parents=True, exist_ok=True)

    enabled_packs = _filter_packs(args.packs)
    results = {}

    for pack_name, source in enabled_packs.items():
        result = _download_pack(pack_name, source, rules_dir)
        results[pack_name] = result

    # Build manifest
    manifest = _build_manifest(results, rules_dir)

    # Create bundle directory
    now = datetime.utcnow()
    bundle_name = now.strftime("nous-%Y-%m-%d")
    bundle_dir = output_dir / bundle_name
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # Copy files with category structure
    security_dir = bundle_dir / "security"
    operations_dir = bundle_dir / "operations"
    security_dir.mkdir(exist_ok=True)
    operations_dir.mkdir(exist_ok=True)

    for pack_name, source in enabled_packs.items():
        if results[pack_name] is None:
            continue

        src_path = rules_dir / source["dest"]
        category = source["category"]
        dest_base = security_dir if category == "security" else operations_dir

        # Preserve relative path structure
        rel_parts = Path(source["dest"]).parts[1:]  # Skip category part
        dest_path = dest_base / Path(*rel_parts) if rel_parts else dest_base / Path(source["dest"]).name

        if src_path.is_file():
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest_path)
        else:
            if dest_path.exists():
                shutil.rmtree(dest_path)
            shutil.copytree(src_path, dest_path)

    # Build derived indexes — sigma-attack-index must be generated before zipping
    _build_sigma_attack_index(rules_dir)
    # Include the generated index in the bundle
    idx_src = rules_dir / "cti" / "sigma-attack-index.json"
    if idx_src.exists():
        idx_dest = security_dir / "attack-index.json"
        shutil.copy2(idx_src, idx_dest)

    # Write manifest
    manifest_path = bundle_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # Create zip
    zip_path = output_dir / f"{bundle_name}.zip"
    shutil.make_archive(str(zip_path.with_suffix("")), "zip", output_dir, bundle_name)

    # Calculate bundle size
    zip_size_mb = zip_path.stat().st_size / (1024 * 1024)
    logger.info(f"Bundle written: {zip_path} ({zip_size_mb:.1f} MB)")

    # Print summary
    _print_summary(results)


def cmd_apply(args):
    """Extract bundle and apply to rules_dir."""
    bundle_zip = Path(args.bundle_zip)
    rules_dir = Path(args.rules_dir)
    rules_dir.mkdir(parents=True, exist_ok=True)

    if not bundle_zip.exists():
        logger.error(f"Bundle not found: {bundle_zip}")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Extract bundle
        with zipfile.ZipFile(bundle_zip, "r") as zf:
            zf.extractall(tmpdir_path)

        # Find manifest
        bundle_name = bundle_zip.stem
        manifest_path = tmpdir_path / bundle_name / "manifest.json"

        if not manifest_path.exists():
            logger.error(f"Manifest not found in bundle: {manifest_path}")
            sys.exit(1)

        with open(manifest_path) as f:
            manifest = json.load(f)

        # Load existing manifest if present
        existing_manifest_path = rules_dir / "intel-manifest.json"
        existing_manifest = {}
        if existing_manifest_path.exists():
            with open(existing_manifest_path) as f:
                existing_manifest = json.load(f)

        # Apply files
        bundle_base = tmpdir_path / bundle_name
        security_applied = 0
        operations_applied = 0
        unchanged = 0

        # Copy security files
        security_src = bundle_base / "security"
        if security_src.exists():
            for src_file in security_src.rglob("*"):
                if src_file.is_file():
                    rel_path = src_file.relative_to(security_src)
                    dest_file = rules_dir / "security" / rel_path
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_file, dest_file)
                    security_applied += 1

        # Copy operations files
        operations_src = bundle_base / "operations"
        if operations_src.exists():
            for src_file in operations_src.rglob("*"):
                if src_file.is_file():
                    rel_path = src_file.relative_to(operations_src)
                    dest_file = rules_dir / "operations" / rel_path
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_file, dest_file)
                    operations_applied += 1

        # Update manifest
        manifest_path_out = rules_dir / "intel-manifest.json"
        with open(manifest_path_out, "w") as f:
            json.dump(manifest, f, indent=2)

        logger.info(
            f"Applied: {security_applied} security files, "
            f"{operations_applied} operations files updated "
            f"({unchanged} unchanged)"
        )


def _print_summary(results: dict):
    """Print summary of downloaded packs by category."""
    security_counts = {}
    operations_counts = {}

    for pack_name, result in results.items():
        if result is None:
            continue

        source = SOURCES[pack_name]
        category = source["category"]

        # Estimate counts based on pack types
        if category == "security":
            if "sigma" in pack_name or "detection" in pack_name:
                security_counts["sigma_rules"] = security_counts.get("sigma_rules", 0) + 100
            if "yara" in pack_name:
                security_counts["yara_rules"] = security_counts.get("yara_rules", 0) + 50
            if "suricata" in pack_name:
                security_counts["suricata_rules"] = security_counts.get("suricata_rules", 0) + 5000
            if "cve" in pack_name:
                security_counts["cves"] = security_counts.get("cves", 0) + 100
        else:
            if "prometheus" in pack_name:
                operations_counts["alert_rules"] = operations_counts.get("alert_rules", 0) + 100
            if "runbook" in pack_name:
                operations_counts["runbooks"] = operations_counts.get("runbooks", 0) + 10
            if "slo" in pack_name:
                operations_counts["slo_examples"] = operations_counts.get("slo_examples", 0) + 5

    print()
    if security_counts:
        parts = ", ".join(f"{v} {k}" for k, v in sorted(security_counts.items()))
        print(f"Security intel:  {parts}")
    if operations_counts:
        parts = ", ".join(f"{v} {k}" for k, v in sorted(operations_counts.items()))
        print(f"Operations:      {parts}")
    print()


# ────────────────────────────────────────────────────────────────────────────
# OCI pull mode (offline-first supply chain)
# ────────────────────────────────────────────────────────────────────────────

def cmd_pull_oci(args):
    """
    Pull the intel bundle OCI artifact from the internal registry and apply it.

    Uses the `oras` CLI (must be on PATH — pre-installed in intel-updater image).
    Equivalent to:
        oras pull <registry>:<tag> --output <tmpdir>
        nous-update apply <tmpdir>/<bundle>.zip --rules-dir <rules_dir>
    """
    registry = args.registry or os.getenv(
        "INTEL_REGISTRY",
        "ghcr.io/getpanops/nous",
    )
    tag   = args.tag or os.getenv("INTEL_TAG", "latest")
    ref   = f"{registry}:{tag}"

    rules_dir = Path(args.rules_dir)
    rules_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        logger.info(f"Pulling OCI artifact {ref} …")
        result = subprocess.run(
            ["oras", "pull", ref, "--output", str(tmpdir_path)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            logger.error(f"oras pull failed:\n{result.stderr}")
            sys.exit(1)
        logger.info(result.stdout.strip())

        # Verify OCI artifact signature before trusting the bundle
        cosign_id = os.getenv(
            "COSIGN_IDENTITY_REGEXP",
            r"https://github\.com/getpanops/nous/\.github/workflows/build-bundle\.yaml@.*",
        )
        cosign_issuer = os.getenv(
            "COSIGN_OIDC_ISSUER",
            "https://token.actions.githubusercontent.com",
        )
        logger.info(f"Verifying cosign signature for {ref} …")
        verify_result = subprocess.run(
            [
                "cosign", "verify",
                "--certificate-identity-regexp", cosign_id,
                "--certificate-oidc-issuer", cosign_issuer,
                ref,
            ],
            capture_output=True, text=True,
        )
        if verify_result.returncode != 0:
            logger.error(f"cosign verify FAILED for {ref}:\n{verify_result.stderr}")
            sys.exit(1)
        logger.info(f"cosign verify OK for {ref}")

        # Find the bundle zip downloaded by oras
        zips = list(tmpdir_path.glob("*.zip"))
        if not zips:
            logger.error(f"No .zip file found in oras pull output at {tmpdir_path}")
            sys.exit(1)

        bundle_zip = zips[0]
        logger.info(f"Applying bundle: {bundle_zip.name}")

        # Reuse existing apply logic
        class _ApplyArgs:
            pass
        apply_args = _ApplyArgs()
        apply_args.bundle_zip = str(bundle_zip)
        apply_args.rules_dir  = str(rules_dir)
        cmd_apply(apply_args)


# ────────────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="nous-update — Knowledge pack downloader and bundler"
    )

    # Determine default rules dir
    default_rules_dir = os.getenv("RULES_DIR", "./rules")

    parser.add_argument(
        "--sources",
        default=None,
        help="Path to sources.yaml catalog "
             "(default: $SOURCES_FILE or <script-dir>/../../sources.yaml)",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # --list-packs
    subparsers.add_parser("list-packs", help="List available packs")

    # --online
    online_parser = subparsers.add_parser("online", help="Download packs to rules dir")
    online_parser.add_argument(
        "--rules-dir", default=default_rules_dir,
        help=f"Where to write downloaded content (default: {default_rules_dir})"
    )
    online_parser.add_argument(
        "--packs", default="",
        help="Comma-separated pack names to update (default: all). "
             "Shorthands: 'security', 'operations'"
    )

    # --bundle
    bundle_parser = subparsers.add_parser("bundle", help="Download and create dated zip bundle")
    bundle_parser.add_argument(
        "output_dir", help="Directory where to write bundles"
    )
    bundle_parser.add_argument(
        "--rules-dir", default=default_rules_dir,
        help=f"Where to write downloaded content (default: {default_rules_dir})"
    )
    bundle_parser.add_argument(
        "--packs", default="",
        help="Comma-separated pack names to update (default: all)"
    )

    # --apply
    apply_parser = subparsers.add_parser("apply", help="Extract and apply bundle")
    apply_parser.add_argument(
        "bundle_zip", help="Path to bundle zip file"
    )
    apply_parser.add_argument(
        "--rules-dir", default=default_rules_dir,
        help=f"Where to install files (default: {default_rules_dir})"
    )

    # pull-oci  (offline-first supply chain — pulls from internal registry)
    pull_oci_parser = subparsers.add_parser(
        "pull-oci",
        help="Pull intel bundle OCI artifact from registry and apply (offline-first mode)",
    )
    pull_oci_parser.add_argument(
        "--registry",
        default=None,
        help="OCI registry reference without tag "
             "(default: $INTEL_REGISTRY or ghcr.io/getpanops/nous)",
    )
    pull_oci_parser.add_argument(
        "--tag",
        default=None,
        help="OCI tag to pull (default: $INTEL_TAG or 'latest')",
    )
    pull_oci_parser.add_argument(
        "--rules-dir", default=default_rules_dir,
        help=f"Where to install files (default: {default_rules_dir})",
    )

    args = parser.parse_args()

    global SOURCES
    sources_file = args.sources or os.getenv(
        "SOURCES_FILE",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sources.yaml"),
    )
    if not os.path.exists(sources_file):
        logger.error(f"sources.yaml not found at {sources_file}. Pass --sources or set SOURCES_FILE.")
        sys.exit(1)
    SOURCES = _load_sources(sources_file)

    if not args.mode or args.mode == "list-packs":
        cmd_list_packs(args)
    elif args.mode == "online":
        cmd_online(args)
    elif args.mode == "bundle":
        cmd_bundle(args)
    elif args.mode == "apply":
        cmd_apply(args)
    elif args.mode == "pull-oci":
        cmd_pull_oci(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
