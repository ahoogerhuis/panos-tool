#!/usr/bin/env python3
"""
PanOS tool
Supports single device (CLI argument) or multiple devices (via .devices file).
Uses the PAN-OS XML API for firmware operations.

Forked from panos-firmware-cleanup.py — same functionality, minus
Panorama support (no --panorama/--fetch-all-devices-from-panorama; the
.devices file is populated by hand or by another process instead).
"""

import requests
import urllib3
import xml.etree.ElementTree as ET  # used for ET.tostring (serialisation only)
try:
    import defusedxml.ElementTree as SafeET
except ImportError:
    import xml.etree.ElementTree as SafeET  # type: ignore[no-redef]
    print("[WARNING] defusedxml not installed — XML parsing is not protected against malicious responses.")
    print("          Run: pip install defusedxml")
import argparse
import sys
import getpass
import os
import re
import time
import datetime
import socket
import urllib.parse
import xml.dom.minidom
import fnmatch
from pathlib import Path
try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


DEVICES_FILE = ".devices"
ENV_KEY = "panos-tool"
DEBUG = False
DEBUG_LOG: str | None = None  # path to debug log file, or None
VERIFY_TLS = True           # set to False via --allow-unverified-tls

MAX_CONSECUTIVE_AUTH_FAILURES = 3  # abort the run rather than lock out the fleet
_consecutive_auth_failures = 0

REBOOT_CONFIRMATION_GRACE_SECONDS = 3600  # warn, don't re-fire, past this age unconfirmed


# ---------------------------------------------------------------------------
# Debug helpers
# ---------------------------------------------------------------------------

def redact_key(key: str) -> str:
    if len(key) <= 12:
        return "***"
    return f"{key[:6]}{'*' * (len(key) - 12)}{key[-6:]}"


def dbg(label: str, content: str) -> None:
    if not DEBUG and not DEBUG_LOG:
        return
    def _redact(m):
        return m.group(1) + redact_key(m.group(2))
    redacted = re.sub(r"(key[=: ]+)([^\s&\"'<]+)", _redact, content)
    lines = []
    lines.append(f"\n  [DEBUG] {label}")
    lines.append(f"  {'─'*66}")
    for line in redacted.splitlines():
        lines.append(f"    {line}")
    lines.append(f"  {'─'*66}")
    block = "\n".join(lines)
    if DEBUG:
        print(block)
    if DEBUG_LOG:
        # Open with O_CREAT|O_APPEND and mode 0o600 so the file is never world-readable
        fd = os.open(DEBUG_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(block + "\n")
        os.chmod(DEBUG_LOG, 0o600)


# ---------------------------------------------------------------------------
# HTTPS API transport
# ---------------------------------------------------------------------------

def api_get(hostname: str, params: dict, timeout: int = 30, api_key: str | None = None) -> requests.Response | None:
    """`api_key`, if given, is sent via the X-PAN-KEY header rather than a
    `key` query parameter, so it never ends up in the device's own URL-based
    access logs."""
    url = f"https://{hostname}/api/"
    headers = {"X-PAN-KEY": api_key} if api_key else {}
    if DEBUG or DEBUG_LOG:
        safe = {k: "<redacted>" if k == "password" else v for k, v in params.items()}
        if api_key:
            safe["X-PAN-KEY"] = redact_key(api_key)
        dbg(f"REQUEST GET  →  {url}", "\n".join(f"{k}: {v}" for k, v in safe.items()))
    try:
        # Build URL manually to avoid double-encoding of XML tags in cmd parameter
        query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        full_url = f"{url}?{query}"
        r = requests.get(full_url, headers=headers, verify=VERIFY_TLS, timeout=timeout)
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] Unable to connect to {hostname}.")
        return None
    except requests.exceptions.Timeout:
        print(f"  [ERROR] Connection to {hostname} timed out.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] Request failed: {e}")
        return None
    if DEBUG or DEBUG_LOG:
        try:
            parsed = SafeET.fromstring(r.text)
            raw = ET.tostring(parsed, encoding="unicode")
            pretty = xml.dom.minidom.parseString(raw).toprettyxml(indent="  ")
            # Remove the XML declaration line minidom adds
            pretty = "\n".join(l for l in pretty.splitlines() if l.strip() and not l.startswith("<?xml"))
            pretty = re.sub(r"(<key>)([^<]+)(</key>)",
                            lambda m: m.group(1) + redact_key(m.group(2)) + m.group(3), pretty)
        except Exception:
            pretty = r.text
        dbg(f"RESPONSE ←  HTTP {r.status_code}", pretty)
    return r


def api_post(hostname: str, data: dict, timeout: int = 30) -> requests.Response | None:
    url = f"https://{hostname}/api/"
    if DEBUG or DEBUG_LOG:
        safe = {k: "<redacted>" if k == "password" else v for k, v in data.items()}
        dbg(f"REQUEST POST →  {url}", "\n".join(f"{k}: {v}" for k, v in safe.items()))
    try:
        # Build body manually to avoid double-encoding of XML tags in cmd parameter
        body = urllib.parse.urlencode(data, quote_via=urllib.parse.quote)
        r = requests.post(url, data=body, verify=VERIFY_TLS, timeout=timeout,
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] Unable to connect to {hostname}.")
        return None
    except requests.exceptions.Timeout:
        print(f"  [ERROR] Connection to {hostname} timed out.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] Request failed: {e}")
        return None
    if DEBUG or DEBUG_LOG:
        try:
            parsed = SafeET.fromstring(r.text)
            raw = ET.tostring(parsed, encoding="unicode")
            pretty = xml.dom.minidom.parseString(raw).toprettyxml(indent="  ")
            # Remove the XML declaration line minidom adds
            pretty = "\n".join(l for l in pretty.splitlines() if l.strip() and not l.startswith("<?xml"))
            pretty = re.sub(r"(<key>)([^<]+)(</key>)",
                            lambda m: m.group(1) + redact_key(m.group(2)) + m.group(3), pretty)
        except Exception:
            pretty = r.text
        dbg(f"RESPONSE ←  HTTP {r.status_code}", pretty)
    return r


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------

def apikey_file(hostname: str, username: str | None = None) -> str:
    safe_host = re.sub(r"[^\w\-.]", "_", hostname)
    if username:
        safe_user = re.sub(r"[^\w\-.]", "_", username)
        return f".apikey-{safe_host}-{safe_user}"
    return f".apikey-{safe_host}"


def automatic_marker_file(hostname: str) -> str:
    """Per-device marker written by --automatic after a successful
    install, so --reboot-pending knows a reboot is owed. The marker only
    triggers a check — the device itself is always re-verified live as
    the source of truth, never the marker's mere existence."""
    safe_host = re.sub(r"[^\w\-.]", "_", hostname)
    return f".automatic-pending-reboot-{safe_host}"


def mark_pending_reboot(hostname: str, sent_at: datetime.datetime | None = None,
                         expected_version: str | None = None) -> None:
    """Create (or overwrite) hostname's --automatic marker at 0600,
    matching every other file this script creates (.apikey-*, debug.log)
    — the marker holds no secret, but there's no reason for it to be the
    one file that follows the process umask instead. O_CREAT's mode only
    applies when the file is newly created, so chmod explicitly too —
    otherwise a marker that somehow pre-existed at a looser mode would
    stay that way.

    With no arguments, marks "install done, reboot not yet attempted"
    (used by --automatic). With both sent_at and expected_version, marks
    "reboot sent, awaiting confirmation" (used by --reboot-pending right
    after firing the reboot) — read back by read_pending_reboot_state()."""
    path = automatic_marker_file(hostname)
    content = ""
    if sent_at is not None and expected_version is not None:
        content = f"sent_at={sent_at.isoformat()}\nexpected_version={expected_version}\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(path, 0o600)


def read_pending_reboot_state(hostname: str) -> tuple[datetime.datetime, str] | None:
    """Return (sent_at, expected_version) if hostname's marker records a
    reboot that was already sent, or None if the marker is empty (install
    done, reboot not yet attempted), missing, or doesn't parse."""
    try:
        with open(automatic_marker_file(hostname)) as f:
            content = f.read()
    except OSError:
        return None
    sent_at = None
    expected_version = None
    for line in content.splitlines():
        if line.startswith("sent_at="):
            try:
                sent_at = datetime.datetime.fromisoformat(line[len("sent_at="):])
            except ValueError:
                return None
        elif line.startswith("expected_version="):
            expected_version = line[len("expected_version="):]
    if sent_at is None or expected_version is None:
        return None
    return sent_at, expected_version


def automatic_lock_file(hostname: str) -> str:
    """Per-device lock for --reboot-pending, guarding against two
    invocations processing the same device at once if one run takes
    longer than the polling interval between invocations."""
    safe_host = re.sub(r"[^\w\-.]", "_", hostname)
    return f".automatic-lock-{safe_host}"


def acquire_automatic_lock(hostname: str, stale_after_seconds: int = 300) -> bool:
    """Atomically acquire hostname's --reboot-pending lock. Returns True
    if acquired (caller must release with release_automatic_lock()) or
    False if another invocation already holds it. A lock older than
    stale_after_seconds is treated as abandoned — e.g. left behind by a
    process that crashed mid-reboot — and reclaimed rather than honored
    forever, since nothing else will ever clear it otherwise."""
    lock_path = automatic_lock_file(hostname)

    def _try_create() -> bool:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        os.close(fd)
        return True

    if _try_create():
        return True
    try:
        age = time.time() - os.path.getmtime(lock_path)
    except OSError:
        return False
    if age <= stale_after_seconds:
        return False
    try:
        os.remove(lock_path)
    except OSError:
        return False
    return _try_create()


def release_automatic_lock(hostname: str) -> None:
    try:
        os.remove(automatic_lock_file(hostname))
    except OSError:
        pass


def load_stored_api_key(hostname: str, username: str | None = None) -> str | None:
    path = apikey_file(hostname, username)
    if os.path.exists(path):
        if os.stat(path).st_mode & 0o177:
            mode = oct(os.stat(path).st_mode & 0o777)
            print(f"  [ERROR] {path} has permissions {mode} — should be 600 or stricter.")
            print(f"          This file contains a live API key and is readable beyond its owner.")
            print(f"          Refusing to proceed until this is fixed. Run: chmod 600 {path}")
            sys.exit(1)
        with open(path) as f:
            key = f.read().strip()
            if key:
                return key
    return None


def save_api_key(hostname: str, api_key: str, username: str | None = None) -> None:
    path = apikey_file(hostname, username)
    # Use os.open so the file is created with 0o600 from the start, never world-readable
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(api_key)
    os.chmod(path, 0o600)
    print(f"  [✓] API key saved to {path}")


def fetch_api_key(hostname: str, username: str, password: str) -> str | None:
    global _consecutive_auth_failures
    print(f"  [*] Fetching API key for {username}@{hostname} ...")
    r = api_post(hostname, {"type": "keygen", "user": username, "password": password}, timeout=15)
    if r is None:
        return None
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Authentication failed: {msg}")
        _consecutive_auth_failures += 1
        if _consecutive_auth_failures >= MAX_CONSECUTIVE_AUTH_FAILURES:
            print(
                f"  [FATAL] {_consecutive_auth_failures} consecutive authentication "
                f"failures — aborting before this locks out the account across the "
                f"rest of the fleet. Check the username/password and try again."
            )
            sys.exit(1)
        return None
    api_key = root.findtext(".//key")
    if not api_key:
        print(f"  [ERROR] No API key found in response.")
        return None
    print(f"  [✓] API key retrieved for {username}.")
    _consecutive_auth_failures = 0
    save_api_key(hostname, api_key, username)
    return api_key


def resolve_api_key(hostname: str, username: str, password_fn) -> str | None:
    """Resolve an API key for the given username: use a stored key if one
    exists, otherwise fetch a fresh one via password_fn()."""
    stored = load_stored_api_key(hostname, username)
    if stored:
        print(f"  [*] Using stored API key from {apikey_file(hostname, username)}")
        return stored
    # No stored key found — fall back to fetching for the provided username
    return fetch_api_key(hostname, username, password_fn())


# ---------------------------------------------------------------------------
# Firmware operations
# ---------------------------------------------------------------------------

def _parse_firmware_entries(root) -> list[dict]:
    """Parse <sw-updates><versions><entry> elements from a software info XML
    response into a deduplicated list of version dicts, unfiltered by
    downloaded status."""
    versions = []
    for entry in root.findall(".//sw-updates/versions/entry"):
        # PAN-OS sometimes returns the literal string "(null)" instead of an
        # empty/missing element for filename and size — treat it as missing.
        raw_filename = entry.findtext("filename")
        raw_size = entry.findtext("size")
        info = {
            "version":      entry.findtext("version") or "N/A",
            "filename":     "" if raw_filename in (None, "", "(null)") else raw_filename,
            "size":         "0" if raw_size in (None, "", "(null)") else raw_size,
            "downloaded":   entry.findtext("downloaded") or "no",
            "current":      entry.findtext("current") or "no",
            "latest":       entry.findtext("latest") or "no",
            "release-type": entry.findtext("release-type") or "",
            "released":     entry.findtext("released-on") or "",
        }
        versions.append(info)
    # Deduplicate — PAN-OS sometimes returns duplicate entries in the XML response
    seen = set()
    return [v for v in versions if not (v["version"] in seen or seen.add(v["version"]))]


def get_downloaded_firmware(hostname: str, api_key: str) -> list[dict] | None:
    params = {
        "type": "op",
        "cmd": "<request><system><software><info></info></software></system></request>",
    }
    r = api_get(hostname, params, timeout=30, api_key=api_key)
    if r is None:
        return None
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] API query failed: {msg}")
        return None
    return [v for v in _parse_firmware_entries(root) if v["downloaded"].lower() == "yes"]


def get_available_firmware(hostname: str, api_key: str) -> list[dict] | None:
    """Like get_downloaded_firmware(), but returns every version PAN-OS
    reports, including ones not yet downloaded — used to check for a newer
    hotfix that hasn't been pulled down yet."""
    params = {
        "type": "op",
        "cmd": "<request><system><software><info></info></software></system></request>",
    }
    r = api_get(hostname, params, timeout=30, api_key=api_key)
    if r is None:
        return None
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] API query failed: {msg}")
        return None
    return _parse_firmware_entries(root)


def format_size(size_str: str) -> str:
    try:
        mb = int(size_str)
    except (ValueError, TypeError):
        return size_str
    return f"{mb / 1024:.1f} GB" if mb >= 1024 else f"{mb} MB"


def is_base_version(version: str, versions: list[dict]) -> bool:
    return any(v["version"] == version and v["release-type"].lower() == "base" for v in versions)


def has_dependents_of_base(base_version: str, versions: list[dict]) -> list[str]:
    parts = base_version.split(".")
    if len(parts) < 2:
        return []
    series = f"{parts[0]}.{parts[1]}."
    return [v["version"] for v in versions
            if v["version"] != base_version and v["version"].startswith(series)]


def delete_firmware(hostname: str, api_key: str, version: str) -> bool:
    params = {
        "type": "op",
        "cmd": f"<delete><software><version>{version}</version></software></delete>",
    }
    r = api_get(hostname, params, timeout=30, api_key=api_key)
    if r is None:
        return False
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"    [ERROR] Delete failed for {version}: {msg}")
        return False
    print(f"    [✓] Successfully deleted PAN-OS {version}")
    return True


def process_deletion_candidates(hostname: str, api_key: str, candidates: list[str],
                                 versions: list[dict], current_version: str | None,
                                 downloaded_versions: set[str]) -> tuple[int, int, int]:
    """Delete each candidate version, applying the same current/base-version
    protection as --delete. Returns (succeeded, failed, skipped) counts."""
    succeeded, failed, skipped = 0, 0, 0
    for version in candidates:
        if version == current_version:
            print(f"    [SKIP] {version} is the currently running version — cannot delete.")
            skipped += 1
        elif version not in downloaded_versions:
            print(f"    [SKIP] {version} is not present on this device.")
            skipped += 1
        elif is_base_version(version, versions):
            dependents = has_dependents_of_base(version, versions)
            if dependents:
                print(f"    [SKIP] {version} is a base version required by: {', '.join(dependents)} — delete dependents first.")
                skipped += 1
            else:
                result = delete_firmware(hostname, api_key, version)
                if result:
                    succeeded += 1
                else:
                    failed += 1
        else:
            result = delete_firmware(hostname, api_key, version)
            if result:
                succeeded += 1
            else:
                failed += 1
    return succeeded, failed, skipped


def prune_hotfix_train(hostname: str, api_key: str, versions: list[dict],
                        current_version: str, keep_count: int,
                        protect_version: str | None = None) -> None:
    """For --automatic: delete downloaded versions in current_version's
    exact hotfix train (same major.minor.maintenance, not the whole
    major.minor family) beyond the keep_count most recent. The base
    version counts against keep_count — it isn't separately exempted
    here, though process_deletion_candidates()'s own base/dependent
    protection (is_base_version/has_dependents_of_base) still applies
    unchanged. protect_version additionally shields a version this run
    just installed but hasn't rebooted into yet, since its `current` flag
    won't flip until reboot."""
    try:
        current_triple = parse_version(current_version)[:3]
    except ValueError:
        return
    downloaded_versions = {v["version"] for v in versions if v["downloaded"].lower() == "yes"}
    train = []
    for version in downloaded_versions:
        try:
            if parse_version(version)[:3] != current_triple:
                continue
        except ValueError:
            continue
        train.append(version)
    train.sort(key=parse_version)
    if len(train) <= keep_count:
        return
    candidates = [v for v in train[:-keep_count] if v != protect_version]
    if not candidates:
        return
    major, minor, maint = current_triple
    print(f"  [*] Pruning hotfix train {major}.{minor}.{maint} — keeping "
          f"{keep_count} most recent, {len(candidates)} candidate(s) for deletion.")
    succeeded, failed, skipped = process_deletion_candidates(
        hostname, api_key, candidates, versions, current_version, downloaded_versions
    )
    print(f"  Pruning complete — Succeeded: {succeeded}  Failed: {failed}  Skipped: {skipped}")


def refresh_software_list(hostname: str, api_key: str) -> bool:
    params = {
        "type": "op",
        "cmd": "<request><system><software><check></check></software></system></request>",
    }
    r = api_get(hostname, params, timeout=60, api_key=api_key)
    if r is None:
        return False
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Refresh failed: {msg}")
        return False
    print(f"  [✓] Software list refreshed successfully")
    return True


def _poll_firmware_job(hostname: str, api_key: str, job_id: str, *, max_attempts: int,
                        interval: float, show_loading_transition: bool = False) -> tuple[str, str]:
    """Poll a PAN-OS job until it finishes or the attempt budget runs out.

    Returns ("ok", ""), ("failed", details), or ("timeout", ""). Only prints
    progress/connection-retry lines — the caller prints its own
    action-specific success/failure/timeout message.

    show_loading_transition prints a distinct message when progress resets
    from 99% to 0% (seen during download, when the file moves into the
    software manager) instead of a plain "0% (status: ...)" line."""
    prev_progress = "?"
    for attempt in range(max_attempts):
        time.sleep(interval)
        poll_params = {
            "type": "op",
            "cmd": f"<show><jobs><id>{job_id}</id></jobs></show>",
        }
        pr = api_get(hostname, poll_params, timeout=30, api_key=api_key)
        if pr is None:
            print(f"  [WARNING] Lost connection while polling job {job_id} — retrying ...")
            continue
        proot = SafeET.fromstring(pr.text)
        # XML API returns structured fields under <result><job>
        job_el   = proot.find(".//job")
        status   = (job_el.findtext("status")   or "").strip() if job_el is not None else ""
        result   = (job_el.findtext("result")   or "").strip() if job_el is not None else ""
        progress = (job_el.findtext("progress") or "?").strip() if job_el is not None else "?"
        details  = (job_el.findtext("details")  or "").strip() if job_el is not None else ""
        if status == "FIN":
            if result == "OK":
                return "ok", ""
            return "failed", (details or result or "Unknown error")
        if show_loading_transition and progress == "0" and prev_progress == "99":
            print(f"  [*] ... loading into software manager (status: {status})")
        else:
            print(f"  [*] ... {progress}% (status: {status})")
        prev_progress = progress
    return "timeout", ""


def download_firmware(hostname: str, api_key: str, version: str) -> bool:
    """Download a specific PAN-OS version to the device and poll for job completion."""
    params = {
        "type": "op",
        "cmd": f"<request><system><software><download><version>{version}</version></download></software></system></request>",
    }
    print(f"  [*] Requesting download of PAN-OS {version} ...")
    r = api_get(hostname, params, timeout=60, api_key=api_key)
    if r is None:
        return False
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Download request failed: {msg}")
        return False

    job_id = root.findtext(".//job")
    if not job_id:
        print(f"  [ERROR] No job ID returned for download request.")
        return False
    if not job_id.strip().isdigit():
        print(f"  [ERROR] Invalid job ID returned: {job_id!r}")
        return False

    print(f"  [*] Download job {job_id} started — polling for completion ...")
    outcome, details = _poll_firmware_job(
        hostname, api_key, job_id, max_attempts=120, interval=5, show_loading_transition=True
    )
    if outcome == "ok":
        print(f"  [\u2713] PAN-OS {version} downloaded successfully.")
        return True
    if outcome == "timeout":
        print(f"  [ERROR] Download job {job_id} timed out after polling.")
    else:
        print(f"  [ERROR] Download job failed: {details}")
    return False



def install_firmware(hostname: str, api_key: str, version: str) -> bool:
    """Install a specific PAN-OS version on the device. Version must already be downloaded."""
    params = {
        "type": "op",
        "cmd": f"<request><system><software><install><version>{version}</version></install></software></system></request>",
    }
    print(f"  [*] Requesting install of PAN-OS {version} ...")
    r = api_get(hostname, params, timeout=60, api_key=api_key)
    if r is None:
        return False
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Install request failed: {msg}")
        return False

    job_id = root.findtext(".//job")
    if not job_id:
        print(f"  [ERROR] No job ID returned for install request.")
        return False
    if not job_id.strip().isdigit():
        print(f"  [ERROR] Invalid job ID returned: {job_id!r}")
        return False

    print(f"  [*] Install job {job_id} started — polling for completion ...")
    # Progress can decrease during install — always show current value
    outcome, details = _poll_firmware_job(hostname, api_key, job_id, max_attempts=180, interval=10)
    if outcome == "ok":
        print(f"  [\u2713] PAN-OS {version} installed successfully. Reboot to activate.")
        return True
    if outcome == "timeout":
        print(f"  [ERROR] Install job {job_id} timed out after polling.")
    else:
        print(f"  [ERROR] Install job failed: {details}")
    return False


def reboot_device(hostname: str, api_key: str) -> bool:
    """Initiate a reboot of the device via the XML API.

    A PAN-OS reboot takes minutes, not seconds — the device answers this
    call normally before it starts shutting anything down, so a dropped
    connection here means something went wrong (auth, network), not that
    the reboot happened too fast to see.

    Once the request is confirmed accepted, does one quick TCP:443 check as
    corroborating evidence — informational only, since a real reboot can
    take well over a minute to actually drop the interface. Kept short
    (~5s) so it doesn't meaningfully slow down rebooting many devices in
    sequence."""
    params = {
        "type": "op",
        "cmd": "<request><restart><system></system></restart></request>",
    }
    print(f"  [*] Sending reboot request ...")
    r = api_get(hostname, params, timeout=15, api_key=api_key)
    if r is None:
        print(f"  [ERROR] No response to reboot request — could not confirm the device is rebooting.")
        return False
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Reboot request failed: {msg}")
        return False
    print(f"  [✓] Reboot initiated — firewall is restarting.")

    time.sleep(3)
    if check_host_reachable(hostname, timeout=2):
        print(f"  [*] {hostname} still reachable on port 443 — normal this early, PAN-OS reboots typically take 1-2+ minutes.")
    else:
        print(f"  [✓] {hostname} is already unreachable on port 443 — reboot confirmed.")
    return True


def get_swm_status(hostname: str, api_key: str) -> str | None:
    """Query partition status via the `debug swm status` op command.
    Returns the raw plain-text table from the response, or None on failure."""
    params = {
        "type": "op",
        "cmd": "<debug><swm><status/></swm></debug>",
    }
    r = api_get(hostname, params, timeout=15, api_key=api_key)
    if r is None:
        return None
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Could not retrieve swm status: {msg}")
        return None
    return root.findtext(".//result") or ""


def find_pending_change_version(swm_status_text: str) -> str | None:
    """Parse `debug swm status` output for a partition in state
    PENDING-CHANGE and return its version, or None if none is staged."""
    for line in swm_status_text.splitlines():
        if "PENDING-CHANGE" in line:
            match = re.search(r'\d+\.\d+\.\d+(?:-h\d{1,2})?', line)
            if match:
                return match.group(0)
    return None


def get_system_info(hostname: str, api_key: str) -> dict | None:
    """Query `show system info` for the currently running software
    version and uptime, used by --reboot-pending to confirm a device
    actually rebooted rather than trusting reboot_device()'s "request
    accepted" alone. XML shape (a <system> element with named children
    including <sw-version> and <uptime>) verified via --debug against a
    real PA-440 on PAN-OS 12.1.10 (see finding #30)."""
    params = {
        "type": "op",
        "cmd": "<show><system><info></info></system></show>",
    }
    r = api_get(hostname, params, timeout=15, api_key=api_key)
    if r is None:
        return None
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Could not retrieve system info: {msg}")
        return None
    return {
        "sw-version": root.findtext(".//sw-version") or "",
        "uptime": root.findtext(".//uptime") or "",
    }


def parse_uptime(uptime_str: str) -> int | None:
    """Parse PAN-OS's `show system info` uptime string ("5 days,
    7:15:50", or just "7:15:50" for under a day) into total seconds.
    Returns None on anything that doesn't match, rather than raising —
    an unparseable uptime should mean "can't confirm a reboot happened,"
    not crash the caller."""
    match = re.match(r'^(?:(\d+)\s+days?,\s+)?(\d{1,2}):(\d{2}):(\d{2})$', uptime_str.strip())
    if not match:
        return None
    days, hours, minutes, seconds = match.groups()
    return (int(days) if days else 0) * 86400 + int(hours) * 3600 + int(minutes) * 60 + int(seconds)


def reboot_confirmed(hostname: str, api_key: str, expected_version: str,
                      sent_at: datetime.datetime) -> bool:
    """True if the device has confirmed rebooting into expected_version
    since sent_at: sw-version matches AND uptime has "wrapped" — the
    reported uptime is less than the time elapsed since the reboot was
    sent, which can only happen if the device's uptime counter reset
    sometime after that, i.e. a genuine reboot occurred (not just a
    device that coincidentally already showed the right version for an
    unrelated reason). False — not yet confirmed — on any missing or
    unparseable data; never assumed confirmed by default."""
    info = get_system_info(hostname, api_key)
    if info is None:
        return False
    if info["sw-version"] != expected_version:
        return False
    uptime_seconds = parse_uptime(info["uptime"])
    if uptime_seconds is None:
        return False
    elapsed_seconds = (datetime.datetime.now() - sent_at).total_seconds()
    return uptime_seconds < elapsed_seconds


def format_swm_status_line(line: str) -> str:
    """PAN-OS returns the literal string "None" as the version for a
    REVERTABLE partition with no installed version. Replace it with
    "(empty)" so the output isn't confusing."""
    return re.sub(r'(?i)\bNone\b', '(empty)', line)


def parse_reboot_time(hhmm: str, now: datetime.datetime | None = None, min_minutes: int = 2) -> datetime.datetime:
    """Parse HH:MM and return the next local occurrence of that time, at
    least min_minutes minutes in the future. Raises ValueError if the format
    is invalid or if the next occurrence would be more than 24 hours away."""
    match = re.match(r'^([01]?\d|2[0-3]):([0-5]\d)$', hhmm)
    if not match:
        raise ValueError(f"Invalid time format: {hhmm!r} — expected HH:MM")
    hour, minute = int(match.group(1)), int(match.group(2))
    now = now or datetime.datetime.now()
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if (candidate - now).total_seconds() < min_minutes * 60:
        candidate += datetime.timedelta(days=1)
    if (candidate - now).total_seconds() > 24 * 3600:
        raise ValueError(
            f"{hhmm} is more than 24 hours away — --reboot-at-time only "
            f"supports scheduling within the next 24 hours"
        )
    return candidate


def parse_duration(value: str) -> int:
    """Parse a duration like '30s', '30m', '1h' into total seconds.
    Rejects a zero amount — a zero-length window would make
    is_within_reboot_window() return False for every possible `now`
    (start <= now < end is never true when end == start), silently and
    permanently disabling --reboot-pending with no error at startup."""
    match = re.match(r'^(\d+)(s|m|h)$', value)
    if not match:
        raise ValueError(f"Invalid duration: {value!r} — expected a number followed by s/m/h, e.g. '30m'")
    amount, unit = int(match.group(1)), match.group(2)
    if amount == 0:
        raise ValueError(f"Invalid duration: {value!r} — must be greater than zero")
    multiplier = {"s": 1, "m": 60, "h": 3600}[unit]
    return amount * multiplier


def is_within_reboot_window(window_start: str, window_length_seconds: int,
                             now: datetime.datetime | None = None) -> bool:
    """True if now falls within today's [window_start, window_start +
    window_length_seconds). Unlike a single fixed instant, a window
    naturally absorbs devices needing a few seconds/minutes to process
    without treating them as "missed" — and a device that doesn't get
    processed before the window closes just waits for tomorrow's
    occurrence, no separate recovery/overshoot handling needed."""
    match = re.match(r'^([01]?\d|2[0-3]):([0-5]\d)$', window_start)
    if not match:
        raise ValueError(f"Invalid time format: {window_start!r} — expected HH:MM")
    hour, minute = int(match.group(1)), int(match.group(2))
    now = now or datetime.datetime.now()
    start = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    end = start + datetime.timedelta(seconds=window_length_seconds)
    return start <= now < end


# ---------------------------------------------------------------------------
# License operations
# ---------------------------------------------------------------------------

def refresh_licenses(hostname: str, api_key: str) -> bool:
    """Trigger a license refresh (`request license fetch`), telling the
    device to check in with the Palo Alto licensing server and pull any
    newly-activated or renewed licenses."""
    params = {
        "type": "op",
        "cmd": "<request><license><fetch></fetch></license></request>",
    }
    r = api_get(hostname, params, timeout=60, api_key=api_key)
    if r is None:
        return False
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] License refresh failed: {msg}")
        return False
    print(f"  [✓] Licenses refreshed successfully")
    return True


# ---------------------------------------------------------------------------
# GlobalProtect client operations
# ---------------------------------------------------------------------------

def validate_gp_client_version(version: str) -> bool:
    """Return True if version looks like a valid GlobalProtect client
    version string. Valid examples: 6.3.3, 6.3.3-c1121 — the `-cNNNN`
    suffix is PAN-OS's own build counter for this product, not a hotfix
    number, so unlike validate_version() there's no digit-count cap."""
    return bool(re.match(r'^\d+\.\d+\.\d+(-c\d+)?$', version))


_GP_CLIENT_ENTRY_RE = re.compile(
    r'^(\S+)\s+(\S+)\s+(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+(yes|no)$'
)


def _parse_gp_client_entries(result_text: str) -> list[dict]:
    """Parse the plain-text table returned by GlobalProtect client
    software `check`/`info` (Version/Size/Released on/Downloaded columns)
    — a different response shape from firmware's `<sw-updates><entry>` XML
    structure. Header/separator/blank lines don't match the pattern and
    are silently skipped."""
    entries = []
    for line in result_text.splitlines():
        m = _GP_CLIENT_ENTRY_RE.match(line.strip())
        if not m:
            continue
        version, size, released, downloaded = m.groups()
        entries.append({"version": version, "size": size, "released": released, "downloaded": downloaded})
    return entries


def refresh_gp_client_software(hostname: str, api_key: str) -> bool:
    """Trigger a GlobalProtect client software catalog refresh (`check`),
    checking in with Palo Alto's update servers for newly-released
    versions."""
    params = {
        "type": "op",
        "cmd": "<request><global-protect-client><software><check></check></software></global-protect-client></request>",
    }
    r = api_get(hostname, params, timeout=60, api_key=api_key)
    if r is None:
        return False
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Refresh failed: {msg}")
        return False
    print(f"  [✓] GlobalProtect client software list refreshed successfully")
    return True


def get_gp_client_versions(hostname: str, api_key: str) -> list[dict] | None:
    """Return the GlobalProtect client software catalog (`info` — cached,
    doesn't contact Palo Alto's update servers). Use
    refresh_gp_client_software() first to pull in newly-released
    versions."""
    params = {
        "type": "op",
        "cmd": "<request><global-protect-client><software><info></info></software></global-protect-client></request>",
    }
    r = api_get(hostname, params, timeout=30, api_key=api_key)
    if r is None:
        return None
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] API query failed: {msg}")
        return None
    return _parse_gp_client_entries(root.findtext(".//result") or "")


def download_gp_client_software(hostname: str, api_key: str, version: str) -> bool:
    """Download a specific GlobalProtect client version to the device and
    poll for job completion."""
    params = {
        "type": "op",
        "cmd": f"<request><global-protect-client><software><download><version>{version}</version></download></software></global-protect-client></request>",
    }
    print(f"  [*] Requesting download of GlobalProtect client {version} ...")
    r = api_get(hostname, params, timeout=60, api_key=api_key)
    if r is None:
        return False
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Download request failed: {msg}")
        return False
    job_id = root.findtext(".//job")
    if not job_id:
        print(f"  [ERROR] No job ID returned for download request.")
        return False
    if not job_id.strip().isdigit():
        print(f"  [ERROR] Invalid job ID returned: {job_id!r}")
        return False
    print(f"  [*] Download job {job_id} started — polling for completion ...")
    outcome, details = _poll_firmware_job(hostname, api_key, job_id, max_attempts=120, interval=5)
    if outcome == "ok":
        print(f"  [✓] GlobalProtect client {version} downloaded successfully.")
        return True
    if outcome == "timeout":
        print(f"  [ERROR] Download job {job_id} timed out after polling.")
    else:
        print(f"  [ERROR] Download job failed: {details}")
    return False


def activate_gp_client_software(hostname: str, api_key: str, version: str) -> bool:
    """Activate a specific GlobalProtect client version — sets which
    package end-user devices receive on their next VPN connection. Version
    must already be downloaded."""
    params = {
        "type": "op",
        "cmd": f"<request><global-protect-client><software><activate><version>{version}</version></activate></software></global-protect-client></request>",
    }
    print(f"  [*] Requesting activation of GlobalProtect client {version} ...")
    r = api_get(hostname, params, timeout=60, api_key=api_key)
    if r is None:
        return False
    root = SafeET.fromstring(r.text)
    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg") or "Unknown error"
        print(f"  [ERROR] Activate request failed: {msg}")
        return False
    job_id = root.findtext(".//job")
    if not job_id:
        print(f"  [ERROR] No job ID returned for activate request.")
        return False
    if not job_id.strip().isdigit():
        print(f"  [ERROR] Invalid job ID returned: {job_id!r}")
        return False
    print(f"  [*] Activate job {job_id} started — polling for completion ...")
    outcome, details = _poll_firmware_job(hostname, api_key, job_id, max_attempts=180, interval=10)
    if outcome == "ok":
        print(f"  [✓] GlobalProtect client {version} activated successfully.")
        return True
    if outcome == "timeout":
        print(f"  [ERROR] Activate job {job_id} timed out after polling.")
    else:
        print(f"  [ERROR] Activate job failed: {details}")
    return False


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_firmware_table(versions: list[dict]) -> None:
    if not versions:
        print("  [INFO] No firmware versions are currently downloaded on this device.")
        return
    def _sort_key(v: dict) -> tuple[int, int, int, int]:
        # parse_version() raises on a malformed string — one bad entry from
        # the device shouldn't crash the whole table, so fall back to
        # sorting it first rather than propagating the exception.
        try:
            return parse_version(v["version"])
        except ValueError:
            return (0, 0, 0, 0)
    versions = sorted(versions, key=_sort_key)
    print(f"  {'VERSION':<18} {'SIZE':<10} {'CURRENT':<10} {'LATEST':<8} {'BASE':<6} {'PREFERRED':<11} FILENAME")
    print(f"  {'-'*18} {'-'*10} {'-'*10} {'-'*8} {'-'*6} {'-'*11} {'-'*30}")
    for v in versions:
        current_flag   = "YES" if v["current"].lower() == "yes" else "no"
        latest_flag    = "YES" if v["latest"].lower() == "yes" else "no"
        base_flag      = "YES" if v["release-type"].lower() == "base" else "no"
        preferred_flag = "YES" if v["release-type"].lower() == "preferred" else "no"
        print(f"  {v['version']:<18} {format_size(v['size']):<10} {current_flag:<10} {latest_flag:<8} {base_flag:<6} {preferred_flag:<11} {v['filename']}")
    base_vers      = [v["version"] for v in versions if v["release-type"].lower() == "base"]
    preferred_vers = [v["version"] for v in versions if v["release-type"].lower() == "preferred"]
    print(f"  Total downloaded: {len(versions)} version(s)", end="")
    if base_vers:
        print(f"  —  Base: {', '.join(base_vers)}", end="")
    if preferred_vers:
        print(f"  —  Preferred: {', '.join(preferred_vers)}", end="")
    print()


def print_gp_client_table(versions: list[dict]) -> None:
    if not versions:
        print("  [INFO] No GlobalProtect client version information available.")
        return
    def _sort_key(v: dict) -> datetime.datetime:
        # Sort by release date rather than parsing the version string —
        # GP client's "-cNNNN" build-counter suffix isn't a hotfix number
        # (validate_version()/parse_version() don't understand it), and
        # release date is both always well-formed here and more useful.
        try:
            return datetime.datetime.strptime(v["released"], "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return datetime.datetime.min
    versions = sorted(versions, key=_sort_key)
    print(f"  {'VERSION':<20} {'SIZE':<8} {'RELEASED':<20} DOWNLOADED")
    print(f"  {'-'*20} {'-'*8} {'-'*20} {'-'*10}")
    for v in versions:
        downloaded_flag = "YES" if v["downloaded"].lower() == "yes" else "no"
        print(f"  {v['version']:<20} {v['size']:<8} {v['released']:<20} {downloaded_flag}")
    downloaded_count = sum(1 for v in versions if v["downloaded"].lower() == "yes")
    print(f"  Total: {len(versions)} version(s), {downloaded_count} downloaded")


# ---------------------------------------------------------------------------
# Device file loader
# ---------------------------------------------------------------------------

def validate_hostname(hostname: str) -> bool:
    """Return True if hostname looks like a valid hostname or IP address.
    Rejects anything with spaces, slashes, angle brackets, quotes, etc."""
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,252}(:\d+)?$', hostname))


def check_host_reachable(hostname: str, port: int = 443, timeout: float = 5.0) -> bool:
    """Return True if hostname:port is reachable via TCP.

    Accepts a bare hostname/IPv4 (optionally "host:port"), or a bracketed
    IPv6 literal ("[::1]" or "[::1]:8443"). A bare, unbracketed IPv6 literal
    has more than one colon and is used as-is with the default port, since
    colons can't be unambiguously split from a port without brackets."""
    host = hostname
    try:
        if hostname.startswith("["):
            end = hostname.find("]")
            if end != -1:
                host = hostname[1:end]
                rest = hostname[end + 1:]
                if rest.startswith(":"):
                    port = int(rest[1:])
        elif hostname.count(":") == 1:
            host, _, port_str = hostname.partition(":")
            port = int(port_str)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, ValueError):
        return False


def validate_version(version: str) -> bool:
    """Return True if version looks like a valid PAN-OS version string.
    Valid examples: 11.2.1, 10.1.10-h21, 11.2.1-h3"""
    return bool(re.match(r'^\d+\.\d+\.\d+(-h\d{1,2})?$', version))


def parse_version(version: str) -> tuple[int, int, int, int]:
    """Parse a PAN-OS version string into a comparable tuple.
    '11.2.10-h3' -> (11, 2, 10, 3); '11.2.10' -> (11, 2, 10, 0)."""
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:-h(\d{1,2}))?$', version)
    if not match:
        raise ValueError(f"Cannot parse version string: {version!r}")
    major, minor, maint, hotfix = match.groups()
    return (int(major), int(minor), int(maint), int(hotfix or 0))


def version_lt(a: str, b: str) -> bool:
    """Return True if version `a` is strictly older than version `b`."""
    return parse_version(a) < parse_version(b)


def filter_malformed_versions(versions: list[dict]) -> tuple[list[dict], int]:
    """Drop any entry whose "version" field isn't a valid PAN-OS version
    string, so callers that compare/sort with version_lt()/parse_version()
    (which raise on bad input) don't crash on a malformed device-reported
    entry. Returns (filtered list, number of entries dropped)."""
    valid = [v for v in versions if validate_version(v["version"])]
    return valid, len(versions) - len(valid)


def find_next_hotfix(current_version: str, versions: list[dict]) -> dict | None:
    """Return the highest-hotfix entry sharing current_version's exact
    major.minor.maintenance triple with a strictly higher hotfix number,
    or None if none exists. Raises ValueError if current_version itself
    doesn't parse (entries that don't parse are silently skipped, same
    as elsewhere)."""
    current_tuple = parse_version(current_version)
    candidates = []
    for v in versions:
        try:
            v_tuple = parse_version(v["version"])
        except ValueError:
            continue
        if v_tuple[:3] == current_tuple[:3] and v_tuple[3] > current_tuple[3]:
            candidates.append((v_tuple, v))
    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[0])
    return candidates[-1][1]


def is_baked_long_enough(released: str, min_age_days: int) -> bool:
    """Return True if a version's released-on timestamp is at least
    min_age_days old. PAN-OS reports released-on in UTC — verified by
    comparing output across devices with no timezone configured, CEST,
    and EEST, all of which returned identical timestamps for the same
    catalog entries — so this compares against UTC now, not local time,
    to avoid an error of up to the host's UTC offset on a gate that
    decides whether firmware installs itself automatically. False on an
    unparseable/empty timestamp — treat unknown release date as not yet
    baked, never as automatically ready."""
    try:
        released_dt = datetime.datetime.strptime(
            released, "%Y/%m/%d %H:%M:%S"
        ).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return False
    return (datetime.datetime.now(datetime.timezone.utc) - released_dt).days >= min_age_days


def load_devices_file(path: str) -> list[str]:
    if not os.path.exists(path):
        print(f"[ERROR] Devices file '{path}' not found.")
        sys.exit(1)
    devices = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if not validate_hostname(line):
                    print(f"[WARNING] Skipping invalid hostname in '{path}': {line!r}")
                    continue
                if "." not in line:
                    print(f"[WARNING] '{line}' in '{path}' appears to be a bare hostname — connections may fail if DNS search domain is not configured.")
                devices.append(line)
    if not devices:
        print(f"[ERROR] No devices found in '{path}'.")
        sys.exit(1)
    return devices


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

def load_env_file() -> str | None:
    """Load credentials, checking three fixed locations in order (first
    match wins, no directory traversal): a plain .env in the current
    directory, a script-specific ~/.env.<ENV_KEY>, then a generic ~/.env.
    Returns the path actually loaded, or None if nothing was loaded."""
    if load_dotenv is None:
        print("WARNING: python-dotenv not installed — skipping .env",
              file=sys.stderr)
        return None
    candidates = [
        Path.cwd() / ".env",
        Path.home() / f".env.{ENV_KEY}",
        Path.home() / ".env",
    ]
    for candidate in candidates:
        if candidate.is_file():
            load_dotenv(candidate)
            return str(candidate)
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global DEBUG

    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("hostname", nargs="?", default="device")
    pre_args, _ = pre_parser.parse_known_args()

    parser = argparse.ArgumentParser(
        description=f"PanOS tool — device {pre_args.hostname}"
    )

    device_group = parser.add_mutually_exclusive_group()
    device_group.add_argument("hostname", nargs="?",
                              help="Firewall IP address or hostname. Comma-separated for multiple "
                                   "devices, e.g. fw1,fw2,fw3.")
    device_group.add_argument("--all-devices", action="store_true",
                              help=f"Run against all devices listed in '{DEVICES_FILE}'")

    parser.add_argument("-u", "--username", default=None,
                        help="Username to authenticate as. Required, either here or via "
                             "PANOS_USERNAME in .env — there is no implicit default, so "
                             "routine runs don't fall back to using admin unconsciously.")
    parser.add_argument("-p", "--password", help="Password for -u/--username (will prompt if not provided)")
    parser.add_argument("--allow-unverified-tls", action="store_true",
                        help="Disable TLS certificate verification for HTTPS API calls. "
                             "Use only if the firewall uses a self-signed certificate and you accept the risk.")
    parser.add_argument("--debug", action="store_true",
                        help="Print all API requests. Keys and passwords are redacted.")
    parser.add_argument("--debug-log", action="store_true",
                        help="Append the full API dialogue to debug.log. Keys and passwords are redacted.")

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument(
        "--delete", metavar="VERSION[,VERSION,...]",
        help="Comma-separated list of firmware versions to delete. "
             "Currently running and required base versions are skipped automatically."
    )
    action_group.add_argument(
        "--delete-lt-version", metavar="VERSION",
        help="Delete all downloaded non-base versions strictly older than VERSION. "
             "Currently running and required base versions are skipped automatically."
    )
    action_group.add_argument(
        "--delete-wc-version", metavar="PATTERN",
        help="Delete all downloaded non-base versions matching a shell wildcard pattern, "
             "e.g. '11.2.7*'. Currently running and required base versions are skipped automatically."
    )
    action_group.add_argument(
        "--download", metavar="VERSION",
        help="Download a specific PAN-OS version to the device(s). "
             "Version must match the format 11.2.1 or 11.2.1-h3. "
             "Only this action is performed."
    )
    action_group.add_argument(
        "--install", metavar="VERSION",
        help="Install a specific PAN-OS version on the device(s). "
             "The version must already be downloaded. "
             "Use --reboot to automatically reboot after install. Only this action is performed."
    )
    action_group.add_argument(
        "--list-downloaded-versions", action="store_true",
        help="List firmware versions already downloaded on the device(s). "
             "Does not contact Palo Alto update servers. Only this action is performed."
    )
    action_group.add_argument(
        "--check-for-next-hotfix", action="store_true",
        help="Check whether a higher hotfix exists for the currently running base "
             "version (e.g. 11.2.10-h3 -> 11.2.10-h4), across the full PAN-OS "
             "catalog, not just already-downloaded versions. Combine with --refresh "
             "to check the latest catalog first. Read-only. Only this action is "
             "performed."
    )
    action_group.add_argument(
        "--show-pending", action="store_true",
        help="Show partition state and which version (if any) is staged to activate on the "
             "next reboot. Read-only. Only this action is performed."
    )
    action_group.add_argument(
        "--fetch-key", action="store_true",
        help="Fetch an API key for -u/--username via HTTPS POST and save it to "
             ".apikey-<hostname>-<user>. Password is read from -p, the environment, "
             "or prompted. Only this action is performed."
    )
    action_group.add_argument(
        "--refresh-licenses", action="store_true",
        help="Trigger a license refresh on the device(s), checking in with the Palo "
             "Alto licensing server for newly-activated or renewed licenses. "
             "Only this action is performed."
    )
    action_group.add_argument(
        "--gp-refresh", action="store_true",
        help="Check in with Palo Alto's update servers for newly-released "
             "GlobalProtect client versions. Only this action is performed."
    )
    action_group.add_argument(
        "--gp-list", action="store_true",
        help="List the GlobalProtect client version catalog (cached — does not "
             "contact Palo Alto's update servers; use --gp-refresh first). "
             "Only this action is performed."
    )
    action_group.add_argument(
        "--gp-download", metavar="VERSION",
        help="Download a specific GlobalProtect client version to the device(s). "
             "Version must match the format 6.3.3 or 6.3.3-c1121. "
             "Only this action is performed."
    )
    action_group.add_argument(
        "--gp-activate", metavar="VERSION",
        help="Activate a specific GlobalProtect client version, controlling which "
             "package end-user devices receive on their next VPN connection. "
             "The version must already be downloaded. Only this action is performed."
    )
    action_group.add_argument(
        "--automatic", "--yolo", action="store_true",
        help="Unattended maintenance flow, meant to be invoked daily by cron: gates "
             "on PANOS_AUTOMATIC_WEEKDAY (no-op on any other day), then per device "
             "checks for a newer hotfix on the current base version, downloads and "
             "installs it once it's been out at least PANOS_AUTOMATIC_MIN_AGE_DAYS, "
             "and prunes the hotfix train down to PANOS_AUTOMATIC_KEEP_VERSIONS. "
             "Does not reboot — a successful install is marked pending for --reboot-pending "
             "to handle. All three .env variables are required. REQUIRES --reboot-pending "
             "to also be scheduled in cron — without it, a device with a pending reboot "
             "is skipped by --automatic forever, with no warning. Always refreshes "
             "internally regardless of --refresh, which has no additional effect here. "
             "Only this action is performed."
    )
    action_group.add_argument(
        "--reboot-pending", action="store_true",
        help="Reboot handler for --automatic, meant to be invoked by cron more often "
             "than PANOS_AUTOMATIC_REBOOT_WINDOW_LENGTH (e.g. every 5 minutes for the "
             "30-minute default) — a coarser cadence risks missing a window entirely "
             "if it doesn't align with your cron schedule. For every device with a "
             "pending install from --automatic, reboots it if now falls within "
             "[PANOS_AUTOMATIC_REBOOT_WINDOW_START, +PANOS_AUTOMATIC_REBOOT_WINDOW_LENGTH) "
             "today (defaults: 02:00, 30m) — re-verified live against the device, "
             "not assumed from the pending marker alone. Outside the window, or if a "
             "device can't be reached, it's left for the next invocation to retry, "
             "including on the next day's window if this one closes first. Only this "
             "action is performed."
    )

    parser.add_argument(
        "--reboot", action="store_true",
        help="Reboot the device after a successful --install. "
             "Can only be used together with --install."
    )
    parser.add_argument(
        "--refresh", action="store_true",
        help="Refresh the available software list on the device(s) before the main action. "
             "Can be combined with --download, --delete-lt-version, --delete-wc-version, "
             "--list-downloaded-versions, and --check-for-next-hotfix, in which case the "
             "refresh runs first on each device. Used alone, refreshes and exits."
    )
    parser.add_argument(
        "--reboot-at-time", metavar="HH:MM",
        help="Schedule a reboot at a specific local time (within the next 24 hours, "
             "minimum 2 minutes from now). Verifies API access on each device before "
             "sleeping, then reboots via XML API at the scheduled time. Cannot be "
             "combined with other action switches, except --install (minimum 30 "
             "minutes per device from now, installs immediately, then reboots at "
             "the scheduled time only if install succeeds). Sleeps in the "
             "foreground — run inside screen or tmux."
    )

    args = parser.parse_args()

    if args.reboot and not args.install:
        parser.error("--reboot can only be used together with --install")

    if args.reboot_at_time and any([
        args.delete, args.delete_lt_version, args.delete_wc_version, args.download,
        args.list_downloaded_versions, args.check_for_next_hotfix, args.show_pending,
        args.fetch_key, args.refresh_licenses,
        args.gp_refresh, args.gp_list, args.gp_download, args.gp_activate,
        args.automatic, args.reboot_pending,
    ]):
        parser.error("--reboot-at-time cannot be combined with other action switches (--install is the exception)")

    if not args.hostname and not args.all_devices:
        parser.error("one of the arguments hostname --all-devices is required")

    env_path = load_env_file()
    if env_path and os.path.exists(env_path):
        mode = oct(os.stat(env_path).st_mode & 0o777)
        if os.stat(env_path).st_mode & 0o177:
            print(f"[ERROR] {env_path} has permissions {mode} — should be 600 or stricter.")
            print(f"        This file contains credentials and is readable beyond its owner.")
            print(f"        Refusing to proceed until this is fixed. Run: chmod 600 {env_path}")
            sys.exit(1)

    DEBUG = args.debug
    if DEBUG:
        print("[DEBUG] Debug mode enabled — API keys and passwords are redacted from output.")
    global DEBUG_LOG
    global VERIFY_TLS
    if args.allow_unverified_tls:
        VERIFY_TLS = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("[WARNING] TLS certificate verification is disabled (--allow-unverified-tls).")
    if args.debug_log or os.getenv("DEBUG_TO_FILE") == "1":
        DEBUG_LOG = "debug.log"
        print(f"[DEBUG] Logging API dialogue to {DEBUG_LOG}")
    username = args.username or os.getenv("PANOS_USERNAME")
    if not username:
        print("[ERROR] No username specified — pass -u/--username or set PANOS_USERNAME in .env.")
        sys.exit(1)
    if args.password:
        print("[WARNING] Password supplied via -p/--password is visible in process list and shell history.")
        print("          Consider omitting it and entering it at the prompt instead.")
    password = args.password or os.getenv("PANOS_PASSWORD")

    if args.all_devices:
        devices = load_devices_file(DEVICES_FILE)
        print(f"[*] Loaded {len(devices)} device(s) from '{DEVICES_FILE}'")
    else:
        devices = [h.strip() for h in args.hostname.split(",") if h.strip()]
        for h in devices:
            if not validate_hostname(h):
                print(f"[ERROR] Invalid hostname: {h!r}")
                sys.exit(1)

    # Lazy password — only prompted if no stored key is found
    def get_password() -> str:
        nonlocal password
        if not password:
            password = getpass.getpass(f"Password for {username}: ")
        return password

    # --reboot-at-time (optionally combined with --install VERSION)
    if args.reboot_at_time:
        install_version = None
        if args.install:
            install_version = args.install.strip()
            if not validate_version(install_version):
                print(f"[ERROR] Invalid version string: {install_version!r} — expected format: 11.2.1 or 11.2.1-h3")
                sys.exit(1)

        # Combining with --install needs enough margin for install to finish
        # before the reboot fires. Installs run sequentially, one device at
        # a time, so the floor scales with device count: up to 30 minutes
        # per device on slower hardware (e.g. a PA-440).
        min_minutes = 30 * len(devices) if install_version else 2
        try:
            scheduled = parse_reboot_time(args.reboot_at_time, min_minutes=min_minutes)
        except ValueError as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

        delta = scheduled - datetime.datetime.now()
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes = remainder // 60
        print(f"[*] Reboot scheduled for {args.reboot_at_time} (in {hours}h {minutes}m) on {len(devices)} device(s).")
        print(f"[!] Run this in screen or tmux — this process must stay alive until then.")
        print()

        device_api_keys = {}
        for hostname in devices:
            if not check_host_reachable(hostname):
                print(f"  {hostname} — [SKIP] not reachable on port 443, will not be rebooted.")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  {hostname} — [SKIP] could not authenticate, will not be rebooted.")
                continue
            versions = get_downloaded_firmware(hostname, api_key)
            if versions is None:
                print(f"  {hostname} — [SKIP] could not retrieve firmware info, will not be rebooted.")
                continue
            current_version = next((v["version"] for v in versions if v["current"].lower() == "yes"), None)

            if install_version:
                downloaded = any(
                    v["version"] == install_version and v["downloaded"].lower() == "yes" for v in versions
                )
                if not downloaded:
                    print(f"  {hostname} — [SKIP] PAN-OS {install_version} is not downloaded, will not be installed or rebooted.")
                    continue
                print(f"  {hostname} — currently {current_version}, will install {install_version} before reboot")
            else:
                swm_status = get_swm_status(hostname, api_key)
                pending_version = find_pending_change_version(swm_status) if swm_status else None
                if pending_version:
                    print(f"  {hostname} — currently {current_version}, will activate on reboot: {pending_version} (PENDING-CHANGE)")
                else:
                    print(f"  {hostname} — currently {current_version}, no version pending — reboot may not activate anything new")
            device_api_keys[hostname] = api_key

        if not device_api_keys:
            print(f"\n[ERROR] No devices passed pre-flight checks — aborting scheduled reboot.")
            sys.exit(1)

        if install_version:
            print(f"\n[*] Installing PAN-OS {install_version} on {len(device_api_keys)} device(s) before the scheduled reboot ...")
            installed = {}
            for hostname, api_key in device_api_keys.items():
                print(f"\n{'='*70}")
                print(f"  Device: {hostname}")
                print(f"{'='*70}")
                if install_firmware(hostname, api_key, install_version):
                    installed[hostname] = api_key
                else:
                    print(f"  [ERROR] Install failed on {hostname} — will not be rebooted.")
            device_api_keys = installed
            if not device_api_keys:
                print(f"\n[ERROR] Install failed on all devices — aborting scheduled reboot.")
                sys.exit(1)

        # Don't carry resolved API keys across the sleep — it can run for up
        # to ~24 hours. Remember only which devices are ready, and resolve a
        # fresh key for each right before rebooting it. In practice this is
        # a cheap on-disk key-file read, not a re-prompt: resolving a key
        # during pre-flight/install above already persisted it to
        # .apikey-<hostname>-<user> (0600), so nothing here requires
        # interactive input from an unattended run.
        ready_devices = list(device_api_keys.keys())
        del device_api_keys

        print(f"\n[*] Sleeping until {args.reboot_at_time} ...")
        seconds_to_wait = (scheduled - datetime.datetime.now()).total_seconds()
        if seconds_to_wait > 0:
            time.sleep(seconds_to_wait)

        print(f"[*] {args.reboot_at_time} reached — rebooting device(s) ...")
        for hostname in ready_devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [ERROR] Could not re-authenticate after the wait — skipping reboot.")
                continue
            reboot_device(hostname, api_key)
        return

    # --fetch-key
    if args.fetch_key:
        print(f"[*] Fetching API key for {username} on {len(devices)} device(s) ...")
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            fetch_api_key(hostname, username, get_password())
            print()
        return

    # --refresh-licenses
    if args.refresh_licenses:
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            refresh_licenses(hostname, api_key)
            print()
        return

    # --gp-refresh
    if args.gp_refresh:
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            refresh_gp_client_software(hostname, api_key)
            print()
        return

    # --gp-list
    if args.gp_list:
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            versions = get_gp_client_versions(hostname, api_key)
            if versions is None:
                print(f"  [SKIP] Could not retrieve GlobalProtect client info — skipping device.\n")
                continue
            print_gp_client_table(versions)
            print()
        return

    # --gp-download
    if args.gp_download:
        version = args.gp_download.strip()
        if not validate_gp_client_version(version):
            print(f"[ERROR] Invalid version string: {version!r} — expected format: 6.3.3 or 6.3.3-c1121")
            sys.exit(1)
        print(f"[*] Downloading GlobalProtect client {version} on {len(devices)} device(s) ...")
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            download_gp_client_software(hostname, api_key, version)
            print()
        return

    # --gp-activate
    if args.gp_activate:
        version = args.gp_activate.strip()
        if not validate_gp_client_version(version):
            print(f"[ERROR] Invalid version string: {version!r} — expected format: 6.3.3 or 6.3.3-c1121")
            sys.exit(1)
        print(f"[*] Activating GlobalProtect client {version} on {len(devices)} device(s) ...")
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            versions = get_gp_client_versions(hostname, api_key)
            if versions is None:
                print(f"  [SKIP] Could not retrieve GlobalProtect client info — skipping device.\n")
                continue
            if not any(v["version"] == version and v["downloaded"].lower() == "yes" for v in versions):
                print(f"  [SKIP] GlobalProtect client {version} is not downloaded — run --gp-download {version} first.\n")
                continue
            activate_gp_client_software(hostname, api_key, version)
            print()
        return

    # --automatic / --yolo
    if args.automatic:
        weekday_raw = os.getenv("PANOS_AUTOMATIC_WEEKDAY")
        valid_weekdays = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
        weekday = (weekday_raw or "").strip().lower()
        if weekday not in valid_weekdays:
            print(f"[ERROR] PANOS_AUTOMATIC_WEEKDAY must be set in .env to a day name "
                  f"like 'sunday' — got {weekday_raw!r}.")
            sys.exit(1)

        min_age_raw = (os.getenv("PANOS_AUTOMATIC_MIN_AGE_DAYS") or "").strip()
        if not min_age_raw.isdigit():
            print(f"[ERROR] PANOS_AUTOMATIC_MIN_AGE_DAYS must be set in .env to a "
                  f"non-negative integer — got {min_age_raw!r}.")
            sys.exit(1)
        min_age_days = int(min_age_raw)

        keep_versions_raw = (os.getenv("PANOS_AUTOMATIC_KEEP_VERSIONS", "3") or "").strip()
        if not keep_versions_raw.isdigit() or int(keep_versions_raw) < 1:
            print(f"[ERROR] PANOS_AUTOMATIC_KEEP_VERSIONS must be a positive integer "
                  f"— got {keep_versions_raw!r}.")
            sys.exit(1)
        keep_versions = int(keep_versions_raw)

        today = datetime.datetime.now().strftime("%A").lower()

        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")

            if os.path.exists(automatic_marker_file(hostname)):
                print(f"  [*] A reboot is already pending from a previous run — "
                      f"skipping until --reboot-pending handles it.\n")
                continue

            if today != weekday:
                print(f"  [*] Today ({today}) is not {weekday} — nothing to do.\n")
                continue

            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue

            refresh_software_list(hostname, api_key)
            versions = get_available_firmware(hostname, api_key)
            if versions is None:
                print(f"  [SKIP] Could not retrieve firmware info — skipping device.\n")
                continue
            versions, num_malformed = filter_malformed_versions(versions)
            if num_malformed:
                print(f"  [WARNING] Ignoring {num_malformed} entr{'y' if num_malformed == 1 else 'ies'} "
                      f"with a malformed version string.")
            current_version = next((v["version"] for v in versions if v["current"].lower() == "yes"), None)
            if not current_version:
                print(f"  [SKIP] Could not determine the currently running version.\n")
                continue

            installed_version = None
            try:
                next_hotfix = find_next_hotfix(current_version, versions)
            except ValueError:
                print(f"  [SKIP] Could not parse currently running version {current_version!r}.\n")
                continue
            if next_hotfix is None:
                print(f"  [*] No newer hotfix available for {current_version}.")
            elif not is_baked_long_enough(next_hotfix["released"], min_age_days):
                print(f"  [*] Newer hotfix {next_hotfix['version']} found but not baked "
                      f"{min_age_days}+ day(s) yet (released {next_hotfix['released'] or 'unknown'}).")
            else:
                target = next_hotfix["version"]
                ok = True
                if next_hotfix["downloaded"].lower() != "yes":
                    ok = download_firmware(hostname, api_key, target)
                if ok:
                    ok = install_firmware(hostname, api_key, target)
                if ok:
                    installed_version = target
                    versions = get_available_firmware(hostname, api_key) or versions
                else:
                    print(f"  [ERROR] Automatic install of {target} failed.")

            prune_hotfix_train(hostname, api_key, versions, current_version, keep_versions,
                                protect_version=installed_version)

            if installed_version:
                mark_pending_reboot(hostname)
                print(f"  [*] Marked pending reboot for --reboot-pending to handle.")
            print()
        return

    # --reboot-pending
    if args.reboot_pending:
        window_start_raw = os.getenv("PANOS_AUTOMATIC_REBOOT_WINDOW_START", "02:00")
        window_start = (window_start_raw or "").strip()
        if not re.match(r'^([01]?\d|2[0-3]):([0-5]\d)$', window_start):
            print(f"[ERROR] PANOS_AUTOMATIC_REBOOT_WINDOW_START must be HH:MM "
                  f"— got {window_start_raw!r}.")
            sys.exit(1)

        window_length_raw = (os.getenv("PANOS_AUTOMATIC_REBOOT_WINDOW_LENGTH", "30m") or "").strip()
        try:
            window_length_seconds = parse_duration(window_length_raw)
        except ValueError as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

        for hostname in devices:
            marker_path = automatic_marker_file(hostname)
            if not os.path.exists(marker_path):
                continue

            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")

            if not acquire_automatic_lock(hostname):
                print(f"  [*] Another --reboot-pending invocation appears to be "
                      f"handling this device — skipping.\n")
                continue
            try:
                state = read_pending_reboot_state(hostname)
                if state is not None:
                    # Phase 2: a reboot was already sent — confirm it actually
                    # landed rather than firing another one at a device that
                    # might still be mid-boot from the first. Not window-gated:
                    # confirming isn't a new maintenance action, so there's no
                    # reason to delay it until tomorrow's window.
                    #
                    # elapsed_seconds/grace_exceeded are computed up front,
                    # before the reachability/auth checks below, so a device
                    # stuck unreachable or unauthenticatable past the grace
                    # period still escalates to the same persistent [WARNING]
                    # as one that's reachable but never confirms — rather
                    # than that being masked by an endlessly-repeating
                    # routine "not reachable"/"could not authenticate" line
                    # (finding #32).
                    sent_at, expected_version = state
                    elapsed_seconds = (datetime.datetime.now() - sent_at).total_seconds()
                    grace_exceeded = elapsed_seconds > REBOOT_CONFIRMATION_GRACE_SECONDS

                    reachable = check_host_reachable(hostname)
                    api_key = resolve_api_key(hostname, username, get_password) if reachable else None

                    if reachable and api_key and reboot_confirmed(hostname, api_key, expected_version, sent_at):
                        print(f"  [✓] Confirmed rebooted into {expected_version} — clearing marker.\n")
                        os.remove(marker_path)
                        continue

                    if grace_exceeded:
                        detail = ""
                        if not reachable:
                            detail = " — device is also currently unreachable"
                        elif not api_key:
                            detail = " — could not authenticate to check"
                        print(f"  [WARNING] Reboot sent {elapsed_seconds / 3600:.1f}h ago, still not "
                              f"confirmed on {expected_version}{detail} — check the device manually.\n")
                    elif not reachable:
                        print(f"  [*] {hostname} is not reachable — will check again next run.\n")
                    elif not api_key:
                        print(f"  [*] Could not authenticate — will check again next run.\n")
                    else:
                        print(f"  [*] Reboot sent, not confirmed yet — will check again next run.\n")
                    continue

                # Phase 1: no reboot sent yet — verify one is still actually
                # pending, and fire it if we're in today's window.
                if not is_within_reboot_window(window_start, window_length_seconds):
                    print(f"  [*] Outside today's reboot window ({window_start}, "
                          f"{window_length_raw}) — will check again next run.\n")
                    continue

                if not check_host_reachable(hostname):
                    print(f"  [SKIP] {hostname} is not reachable — will retry next run.\n")
                    continue
                api_key = resolve_api_key(hostname, username, get_password)
                if not api_key:
                    print(f"  [SKIP] Could not authenticate — will retry next run.\n")
                    continue
                swm_status = get_swm_status(hostname, api_key)
                if swm_status is None:
                    print(f"  [SKIP] Could not retrieve partition status — will retry next run.\n")
                    continue
                pending_version = find_pending_change_version(swm_status)
                if not pending_version:
                    print(f"  [*] Nothing pending anymore — clearing stale marker.\n")
                    os.remove(marker_path)
                    continue
                print(f"  [*] {pending_version} is pending — rebooting.")
                success = reboot_device(hostname, api_key)
                if success:
                    mark_pending_reboot(hostname, sent_at=datetime.datetime.now(),
                                         expected_version=pending_version)
                print()
            finally:
                release_automatic_lock(hostname)
        return

    # --list-downloaded-versions
    if args.list_downloaded_versions:
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            if args.refresh:
                refresh_software_list(hostname, api_key)
            versions = get_downloaded_firmware(hostname, api_key)
            if versions is None:
                print(f"  [SKIP] Could not retrieve firmware info — skipping device.\n")
                continue
            print_firmware_table(versions)
            print()
        return

    # --check-for-next-hotfix
    if args.check_for_next_hotfix:
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            if args.refresh:
                refresh_software_list(hostname, api_key)
            versions = get_available_firmware(hostname, api_key)
            if versions is None:
                print(f"  [SKIP] Could not retrieve firmware info — skipping device.\n")
                continue
            current_version = next((v["version"] for v in versions if v["current"].lower() == "yes"), None)
            if not current_version:
                print(f"  [SKIP] Could not determine the currently running version.\n")
                continue
            try:
                highest = find_next_hotfix(current_version, versions)
            except ValueError:
                print(f"  [SKIP] Could not parse currently running version {current_version!r}.\n")
                continue
            print(f"  Currently running: {current_version}")
            if highest:
                status = "already downloaded" if highest["downloaded"].lower() == "yes" else "not downloaded — use --download to fetch it"
                print(f"  [*] Newer hotfix available: {highest['version']} ({status})")
            else:
                print(f"  [*] No newer hotfix available for this base version.")
            print()
        return

    # --show-pending
    if args.show_pending:
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            swm_status = get_swm_status(hostname, api_key)
            if swm_status is None:
                print(f"  [SKIP] Could not retrieve partition status — skipping device.\n")
                continue
            for line in swm_status.splitlines():
                print(f"  {format_swm_status_line(line)}")
            pending_version = find_pending_change_version(swm_status)
            if pending_version:
                print(f"\n  [*] Pending activation on reboot: {pending_version}")
            else:
                print(f"\n  [*] No version pending — reboot will not change the running version.")
            print()
        return

    # --refresh alone (no other action requested) — refresh and exit, as before.
    # When combined with --download, --delete-lt-version, --delete-wc-version,
    # --list-downloaded-versions, or --check-for-next-hotfix, the refresh instead
    # runs first inside that action's own per-device loop.
    combinable_with_refresh = bool(args.download or args.delete_lt_version or args.delete_wc_version or args.list_downloaded_versions or args.check_for_next_hotfix)
    other_action_requested = bool(args.install or args.delete)
    if args.refresh and not combinable_with_refresh and not other_action_requested:
        print(f"[*] Refreshing software list on {len(devices)} device(s) ...")
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            refresh_software_list(hostname, api_key)
            print()
        return

    # --download
    if args.download:
        version = args.download.strip()
        if not validate_version(version):
            print(f"[ERROR] Invalid version string: {version!r} — expected format: 11.2.1 or 11.2.1-h3")
            sys.exit(1)
        print(f"[*] Downloading PAN-OS {version} on {len(devices)} device(s) ...")
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            if args.refresh:
                refresh_software_list(hostname, api_key)
            download_firmware(hostname, api_key, version)
            print()
        return

    # --delete-lt-version
    if args.delete_lt_version:
        threshold = args.delete_lt_version.strip()
        if not validate_version(threshold):
            print(f"[ERROR] Invalid version string: {threshold!r} — expected format: 11.2.1 or 11.2.1-h3")
            sys.exit(1)
        print(f"[*] Deleting versions older than {threshold} on {len(devices)} device(s) ...")
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            if args.refresh:
                refresh_software_list(hostname, api_key)
            versions = get_downloaded_firmware(hostname, api_key)
            if versions is None:
                print(f"  [SKIP] Could not retrieve firmware info — skipping device.\n")
                continue
            versions, num_malformed = filter_malformed_versions(versions)
            if num_malformed:
                print(f"  [WARNING] Ignoring {num_malformed} entr{'y' if num_malformed == 1 else 'ies'} "
                      f"with a malformed version string.")
            downloaded_versions = {v["version"] for v in versions}
            current_version = next((v["version"] for v in versions if v["current"].lower() == "yes"), None)
            candidates = sorted(
                {v["version"] for v in versions
                 if v["release-type"].lower() != "base" and version_lt(v["version"], threshold)},
                key=parse_version
            )
            if not candidates:
                print(f"  [INFO] No downloaded non-base versions older than {threshold}.")
                print()
                continue
            print(f"  Deletion candidates (< {threshold}): {', '.join(candidates)}")
            print(f"  {'-'*66}")
            succeeded, failed, skipped = process_deletion_candidates(
                hostname, api_key, candidates, versions, current_version, downloaded_versions
            )
            print(f"  Deletion complete — Succeeded: {succeeded}  Failed: {failed}  Skipped: {skipped}")
            print()
        return

    # --delete-wc-version
    if args.delete_wc_version:
        pattern = args.delete_wc_version.strip()
        print(f"[*] Deleting versions matching '{pattern}' on {len(devices)} device(s) ...")
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            if args.refresh:
                refresh_software_list(hostname, api_key)
            versions = get_downloaded_firmware(hostname, api_key)
            if versions is None:
                print(f"  [SKIP] Could not retrieve firmware info — skipping device.\n")
                continue
            versions, num_malformed = filter_malformed_versions(versions)
            if num_malformed:
                print(f"  [WARNING] Ignoring {num_malformed} entr{'y' if num_malformed == 1 else 'ies'} "
                      f"with a malformed version string.")
            downloaded_versions = {v["version"] for v in versions}
            current_version = next((v["version"] for v in versions if v["current"].lower() == "yes"), None)
            candidates = sorted(
                {v["version"] for v in versions
                 if v["release-type"].lower() != "base" and fnmatch.fnmatch(v["version"], pattern)},
                key=parse_version
            )
            if not candidates:
                print(f"  [INFO] No downloaded non-base versions matching '{pattern}'.")
                print()
                continue
            print(f"  Deletion candidates ({pattern}): {', '.join(candidates)}")
            print(f"  {'-'*66}")
            succeeded, failed, skipped = process_deletion_candidates(
                hostname, api_key, candidates, versions, current_version, downloaded_versions
            )
            print(f"  Deletion complete — Succeeded: {succeeded}  Failed: {failed}  Skipped: {skipped}")
            print()
        return

    # --install
    if args.install:
        version = args.install.strip()
        if not validate_version(version):
            print(f"[ERROR] Invalid version string: {version!r} — expected format: 11.2.1 or 11.2.1-h3")
            sys.exit(1)
        print(f"[*] Installing PAN-OS {version} on {len(devices)} device(s) ...")
        for hostname in devices:
            print(f"\n{'='*70}")
            print(f"  Device: {hostname}")
            print(f"{'='*70}")
            if not check_host_reachable(hostname):
                print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
                continue
            api_key = resolve_api_key(hostname, username, get_password)
            if not api_key:
                print(f"  [SKIP] Could not authenticate — skipping device.\n")
                continue
            versions = get_downloaded_firmware(hostname, api_key)
            if versions is None:
                print(f"  [SKIP] Could not retrieve firmware info — skipping device.\n")
                continue
            if not any(v["version"] == version for v in versions):
                print(f"  [SKIP] PAN-OS {version} is not downloaded — run --download {version} first.\n")
                continue
            success = install_firmware(hostname, api_key, version)
            if success and args.reboot:
                reboot_device(hostname, api_key)
            print()
        return

    # Default: list firmware (and optionally delete)
    to_delete = [v.strip() for v in args.delete.split(",") if v.strip()] if args.delete else []
    for version in to_delete:
        if not validate_version(version):
            print(f"[ERROR] Invalid version string: {version!r} — expected format: 11.2.1 or 11.2.1-h3")
            sys.exit(1)

    for hostname in devices:
        print(f"\n{'='*70}")
        print(f"  Device: {hostname}")
        print(f"{'='*70}")

        if not check_host_reachable(hostname):
            print(f"  [SKIP] {hostname} is not reachable on port 443 — skipping.\n")
            continue

        api_key = resolve_api_key(hostname, username, get_password)
        if not api_key:
            print(f"  [SKIP] Could not authenticate — skipping device.\n")
            continue

        versions = get_downloaded_firmware(hostname, api_key)
        if versions is None:
            print(f"  [SKIP] Could not retrieve firmware info — skipping device.\n")
            continue

        if not to_delete:
            print_firmware_table(versions)
        else:
            downloaded_versions = {v["version"] for v in versions}
            current_version = next((v["version"] for v in versions if v["current"].lower() == "yes"), None)

            print(f"  Deletion request: {', '.join(to_delete)}")
            print(f"  {'-'*66}")

            succeeded, failed, skipped = process_deletion_candidates(
                hostname, api_key, to_delete, versions, current_version, downloaded_versions
            )

            print(f"  Deletion complete — Succeeded: {succeeded}  Failed: {failed}  Skipped: {skipped}")

        print()


if __name__ == "__main__":
    main()

