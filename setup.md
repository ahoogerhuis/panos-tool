# PAN-OS Tool — Setup Guide

This guide covers how to prepare your host to run `panos-tool.py` against a PAN-OS firewall.

---

## 1. Python Setup (Debian 12)

Debian 12 ships with Python 3.11. Dependencies are listed in `requirements.txt`: `requests`, `python-dotenv`, and `defusedxml`.

### Set up a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

To deactivate the venv when done:

```bash
deactivate
```

### Verify the installation

```bash
python3 -c "import requests, dotenv, defusedxml; print('OK')"
```

---

## 2. Configure `.env`

Set the script permissions:

```bash
chmod 700 panos-tool.py
```

Copy the sample file and set permissions:

```bash
cp .env.sample .env
chmod 600 .env
```

The script refuses to run if `.env` (or the API key files under `.apikey-*`)
has permissions wider than 600 — credentials and live API keys should never
be group- or world-readable.

Edit `.env` to configure credentials:

```ini
# Used for all actions unless overridden with -u/-p on the command line
PANOS_USERNAME=admin
PANOS_PASSWORD=YourAdminPassword
```

### Credential resolution order

`.env` files are checked in this order, first match wins (no directory
traversal — each is a single fixed location, not searched for upward):

1. A plain `.env` file in the current directory, if present.
2. A script-specific `~/.env.panos-tool` file in your home directory.
3. A generic `~/.env` file in your home directory.
4. If none provide a value, an interactive password prompt.

The two home-directory tiers work the same regardless of which directory you
run the script from — useful for cron, or for keeping several tools'
credentials in one shared `~/.env` while overriding just this one via
`~/.env.panos-tool`.

---

## 3. Device List

To run against multiple devices, create a `.devices` file with one hostname or IP per line:

```
# Packets flow through walls
# Silent guardian of the net
# Firewall stands watch
firewall1.example.com
firewall2.example.com
192.168.1.1
```

Lines starting with `#` are treated as comments.

### Comma-separated hostnames

For a quick one-off run against a handful of devices, you can skip `.devices`
and `--all-devices` entirely by passing a comma-separated list as the
positional hostname argument:

```bash
./panos-tool.py --list-downloaded-versions fw1.example.com,fw2.example.com,fw3.example.com
```

This works with every device-facing switch (`--fetch-key`, `--list-downloaded-versions`,
`--check-for-next-hotfix`, `--refresh`, `--download`, `--install`, `--delete`,
`--delete-lt-version`, `--delete-wc-version`). Each hostname is validated
individually; an invalid entry aborts the run before anything runs.

This tool has no Panorama integration — I only manage individual PAN-OS
firewalls and have no Panorama to test against. `.devices` is built and
maintained by hand (or by another process external to this tool).

---

## 4. Accounts and Credentials

The script authenticates as whatever account you give it via `-u`/`--username`
and `-p`/`--password`, or via `.env` — there's no built-in notion of a
special "service account," and no implicit default account either. `-u` is
required, either on the command line or as `PANOS_USERNAME` in `.env` — this
is deliberate, so routine runs don't fall back to `admin` unconsciously.
Using your existing admin credentials directly (explicitly, via `-u admin`
or `PANOS_USERNAME=admin`) works fine and is the simplest path.

### Optional: a dedicated least-privilege account

If you'd rather not use `admin` directly (e.g. for an unattended cron job),
create a dedicated account by hand. PAN-OS restricts delete/install/reboot
operations to the superuser role, so a single read-only role can't cover
every action this script performs — if you want write access too, that
account needs `superuser yes`, not a custom role.

Example: a read-only role/account for listing firmware, connect to the
firewall CLI and run in configure mode:

```
set cli config-output-format set
configure

set shared admin-role panos-reader-role description "Read-only role for panos-tool.py"
set shared admin-role panos-reader-role role device xmlapi op enable
set shared admin-role panos-reader-role role device restapi
set shared admin-role panos-reader-role role device webui

set mgt-config users panos-reader description "Read-only account for panos-tool.py"
set mgt-config users panos-reader permissions role-based custom profile panos-reader-role
set mgt-config users panos-reader password
<password>
<password>

commit description 'Add panos-reader account'
exit
```

Then fetch and store an API key for it:

```bash
./panos-tool.py <hostname> --fetch-key -u panos-reader
```

Once a key is stored (`.apikey-<hostname>-<user>`), the script uses it
automatically whenever you pass that same `-u <user>` again — no password
needed until the key expires or is revoked.

---

## 5. Usage

### Listing firmware

```bash
# List downloaded firmware on a single device
./panos-tool.py --list-downloaded-versions <hostname>

# List firmware on all devices
./panos-tool.py --list-downloaded-versions --all-devices
```

### Downloading firmware

```bash
# Download a specific version
./panos-tool.py --download 12.1.5 <hostname>

# Refresh the available software list from Palo Alto update servers, then download
./panos-tool.py --refresh --download 12.1.5 <hostname>
```

### Refreshing the software list

```bash
# Refresh only, then exit
./panos-tool.py --refresh <hostname>
```

`--refresh` can also be combined with `--download`, `--delete-lt-version`, or
`--delete-wc-version` — the refresh runs first on each device, then the main
action follows. Used on its own (as above), it refreshes and exits.

### Installing firmware

```bash
# Install a specific version — version must already be downloaded
./panos-tool.py --install 12.1.5 <hostname>

# Install and reboot automatically after successful install
./panos-tool.py --install 12.1.5 --reboot <hostname>
```

Note: `--reboot` can only be used together with `--install`. A reboot takes 7-10 minutes on typical hardware. The script fires the reboot and exits — it does not wait for the device to come back up.

### Scheduling a reboot

```bash
# Reboot fw1 at 23:00 local time
./panos-tool.py --reboot-at-time 23:00 fw1.example.com

# Also works against multiple devices
./panos-tool.py --reboot-at-time 23:00 fw1.example.com,fw2.example.com
```

`--reboot-at-time HH:MM` schedules a reboot for the next occurrence of that
local time:

- If `HH:MM` is more than 2 minutes away later today, it reboots today.
- Otherwise (already passed today, or under 2 minutes away) it reboots
  tomorrow at that time.
- If the resulting time would be more than 24 hours away, the script exits
  with an error instead of scheduling it — `--reboot-at-time` only supports
  scheduling within the next 24 hours.

Before sleeping, it runs a pre-flight check on every device — reachability,
API authentication, and a firmware-list fetch — and skips any device that
fails one, so a bad credential or unreachable host is caught immediately
rather than discovered hours later at reboot time. It also checks each
device's pending partition (`debug swm status`) and reports which version
(if any) is staged to activate on reboot.

**This process sleeps in the foreground until the scheduled time — run it
inside `screen` or `tmux` so it isn't killed if your terminal disconnects.**

It cannot be combined with other action switches (`--delete`,
`--list-downloaded-versions`, `--show-pending`, etc.) — it's a standalone action, same
as `--reboot` without `--install` would be — **except `--install`**, which
it can be combined with (see below).

#### Combining with `--install`

```bash
# Install 11.2.13-h4, then reboot at 23:00 to activate it — only if install succeeds
./panos-tool.py --install 11.2.13-h4 --reboot-at-time 23:00 fw1.example.com
```

`--install VERSION --reboot-at-time HH:MM` installs immediately (not at
`HH:MM`) and only reboots at the scheduled time if the install succeeds:

- The minimum lead time is **30 minutes per device** instead of a flat 2,
  to leave enough margin for install to finish on slower hardware (up to
  15-20 minutes on a PA-440, for example) before the reboot fires. Installs
  run sequentially, one device at a time, so the floor scales with device
  count — 1 device needs 30 minutes, 2 devices need 60, and so on. This is
  checked once up front against the full device list, not re-checked after
  each install completes.
- Pre-flight checks the requested version is actually downloaded on each
  device (instead of checking the pending partition, which isn't relevant
  yet) — a device where it isn't downloaded is skipped before anything
  happens.
- Install then runs immediately on every device that passed pre-flight,
  with normal job polling.
- Only devices where install succeeds are rebooted at `HH:MM`. If install
  fails everywhere, the scheduled reboot is aborted entirely.

### Checking what's pending activation

```bash
# Show partition state and what will activate on the next reboot
./panos-tool.py --show-pending <hostname>
```

Read-only — queries `debug swm status` and prints the partition table as-is,
followed by a summary of which version (if any) is staged to activate on the
next reboot. This is the same check `--reboot-at-time` runs automatically
before scheduling, exposed here as its own switch for a quick look without
scheduling anything.

### Checking for a newer hotfix

```bash
# Check whether a higher hotfix exists for the currently running base version
./panos-tool.py --check-for-next-hotfix <hostname>

# Refresh the catalog from Palo Alto first, then check
./panos-tool.py --refresh --check-for-next-hotfix <hostname>
```

Read-only. Compares the currently running version (e.g. `11.2.10-h3`)
against the full PAN-OS catalog reported by the device — not just versions
already downloaded — looking for a higher hotfix on the same base version
(`11.2.10-h4`, `11.2.10-h5`, ...). Reports the highest one found and whether
it's already downloaded or would need `--download` first, or that no newer
hotfix is available. `--refresh` is optional here (unlike `--download`,
where it's often desirable to see the latest catalog) — without it, the
check reflects whatever the device last knew from its own refresh history.

### Deleting firmware

```bash
# Delete specific firmware versions
./panos-tool.py --delete 11.1.0,11.1.1 <hostname>

# Delete all downloaded non-base versions strictly older than a given version
./panos-tool.py --delete-lt-version 11.2.13-h2 <hostname>

# Delete all downloaded non-base versions matching a shell wildcard pattern
./panos-tool.py --delete-wc-version "11.2.7*" <hostname>

# Refresh first, then bulk-delete everything older than a version
./panos-tool.py --refresh --delete-lt-version 11.2.13-h2 <hostname>
```

Currently running versions and base versions required by other downloaded versions are skipped automatically for all three deletion switches (`--delete`, `--delete-lt-version`, `--delete-wc-version`). These three are mutually exclusive with each other — only one deletion mode may be used per run.

### Fetching an API key

```bash
# Fetch and store an API key for -u/--username (or PANOS_USERNAME from .env,
# if -u is omitted — one of the two is required)
./panos-tool.py <hostname> --fetch-key

# Fetch a key for a specific account
./panos-tool.py <hostname> --fetch-key -u panos-reader
```

### Refreshing licenses

```bash
# Trigger a license refresh, checking in with the Palo Alto licensing
# server for newly-activated or renewed licenses
./panos-tool.py <hostname> --refresh-licenses
```

Read-only in the sense that it doesn't touch firmware — it just tells the
device to check in with the licensing server. Standalone action, same
mutual-exclusion rules as `--fetch-key`, `--show-pending`, etc.

### GlobalProtect client software

```bash
# Check in with Palo Alto's update servers for newly-released versions
./panos-tool.py <hostname> --gp-refresh

# List the version catalog (cached — doesn't contact Palo Alto)
./panos-tool.py <hostname> --gp-list

# Download a specific version
./panos-tool.py <hostname> --gp-download 6.3.3-c1121

# Activate a specific version — controls which package end-user devices
# receive on their next VPN connection. Must already be downloaded.
./panos-tool.py <hostname> --gp-activate 6.3.3-c1121
```

These are separate from the PAN-OS firmware operations above — a
different product with its own version scheme (`6.3.3-c1121`, a build
counter, not a hotfix number) and its own PAN-OS API commands
(`check`/`info`/`download`/`activate` rather than
`check`/`info`/`download`/`install`). "Activate" is PAN-OS's own term:
`--gp-activate` doesn't install anything on the firewall itself, it sets
which client package gets pushed out on next connection.

### Unattended automatic maintenance (--automatic / --reboot-pending)

```bash
# Daily: checks for a newer hotfix, downloads/installs it, prunes old
# versions. Never reboots — marks the device pending instead.
./panos-tool.py --all-devices --automatic

# Frequent: reboots any device --automatic marked pending, once inside
# today's reboot window.
./panos-tool.py --all-devices --reboot-pending
```

Two separate flags, both meant for cron — see [Scheduling with
Cron](#8-scheduling-with-cron) for the crontab entries and required
`.env` variables. `--automatic`/`--yolo` (same flag, either name works)
decides for itself whether today is a day it should act, so a daily
cron firing is all it needs. `--reboot-pending` needs to be invoked
more often than the reboot window is long, so it doesn't miss a window
that doesn't line up with its own schedule.

See [flows.md](flows.md) for lifecycle diagrams of both flags' per-device
steps and checks.

### Debugging

```bash
# Debug mode — prints all API requests and responses (keys redacted)
./panos-tool.py <hostname> --debug

# Log API dialogue to debug.log
./panos-tool.py <hostname> --debug-log

# Skip TLS certificate verification (for self-signed certs)
./panos-tool.py <hostname> --allow-unverified-tls
```

---

## 6. API Keys

API keys are stored in `.apikey-<hostname>-<username>` files in the working directory, keyed by whichever `-u`/`--username` was used to fetch them. These are listed in `.gitignore` and should never be committed.

There's no distinction between read-only and write operations at the credential level — every action uses whatever account `-u` resolves to (default `admin`). If that account already has a stored API key for a given device, the key is used and no password is needed.

---

## 7. Removing a Dedicated Account

If you created a dedicated account as in section 4 and no longer need it:

```
configure
delete shared admin-role panos-reader-role
delete mgt-config users panos-reader
commit description "Remove panos-reader account"
exit
```

Also delete its local API key files:

```bash
rm .apikey-*-panos-reader
```

---

## 8. Scheduling with Cron

The script is designed to be run unattended. API keys and passwords should be stored in `.env` so no interactive prompts are needed.

### Using crontab (per-user)

Edit the crontab for the user that owns the script:

```bash
crontab -e
```

Example — list firmware on all devices every Monday at 06:00, emailing output to the ops team:

```
MAILTO=vibe-ops@foo.bar
0 6 * * 1 cd /opt/panos-tool && .venv/bin/python panos-tool.py --list-downloaded-versions --all-devices >> logs/firmware.log 2>&1
```

Example — refresh the software list nightly at 02:00:

```
MAILTO=vibe-ops@foo.bar
0 2 * * * cd /opt/panos-tool && .venv/bin/python panos-tool.py --all-devices --refresh >> logs/refresh.log 2>&1
```

### Using /etc/cron.daily

Place a wrapper script in `/etc/cron.daily/`:

```bash
cat > /etc/cron.daily/panos-tool << 'CRONEOF'
#!/bin/bash
cd /opt/panos-tool
.venv/bin/python panos-tool.py --list-downloaded-versions --all-devices >> logs/firmware.log 2>&1
CRONEOF
chmod 700 /etc/cron.daily/panos-tool
```

Set `MAILTO` in `/etc/crontab` or `/etc/cron.d/` if not already configured.

### Using /etc/crontab (system-wide)

```
MAILTO=vibe-ops@foo.bar
0 6 * * 1 root cd /opt/panos-tool && .venv/bin/python panos-tool.py --list-downloaded-versions --all-devices >> logs/firmware.log 2>&1
```

### Notes

- Always use the full path to the venv Python interpreter to avoid PATH issues
- Create the `logs/` directory before first run: `mkdir -p /opt/panos-tool/logs`
- The `.env` file must be readable by the user running the cron job
- Use `DEBUG_TO_FILE=1` in `.env` to enable API debug logging to `debug.log` for troubleshooting

### Unattended maintenance with --automatic/--yolo and --reboot-pending

`--automatic` and `--reboot-pending` split install and reboot into two
separate cron entries, on purpose — neither one ever sleeps or blocks
waiting for a specific moment, so neither can hold up a cron slot:

```
MAILTO=vibe-ops@foo.bar
# Daily: check for a newer hotfix, download/install it, prune old versions
0 2 * * * cd /opt/panos-tool && .venv/bin/python panos-tool.py --all-devices --automatic >> logs/automatic.log 2>&1

# Every 5 minutes: reboot anything --automatic marked pending, once the
# daily reboot window opens
*/5 * * * * cd /opt/panos-tool && .venv/bin/python panos-tool.py --all-devices --reboot-pending >> logs/reboot-pending.log 2>&1
```

`PANOS_AUTOMATIC_WEEKDAY` and `PANOS_AUTOMATIC_MIN_AGE_DAYS` are both
required for `--automatic`; `PANOS_AUTOMATIC_KEEP_VERSIONS` is optional
(default `3`). See `.env.sample`:

| Variable | Purpose |
|---|---|
| `PANOS_AUTOMATIC_WEEKDAY` | Day of week `--automatic` is allowed to act (e.g. `sunday`) — any other day it's a no-op, so the crontab entry above can safely fire every day |
| `PANOS_AUTOMATIC_MIN_AGE_DAYS` | How long a newer hotfix must have been out before it's auto-installed |
| `PANOS_AUTOMATIC_KEEP_VERSIONS` | Versions to keep per hotfix train when pruning (default `3`); the base version counts against this |
| `PANOS_AUTOMATIC_REBOOT_WINDOW_START` | Daily reboot window start, `HH:MM` (default `02:00`) |
| `PANOS_AUTOMATIC_REBOOT_WINDOW_LENGTH` | Reboot window length — a number with a unit suffix: `30s`, `30m`, `1h` (default `30m`) |

On its scheduled day, `--automatic` refreshes the software list per
device, checks for a newer hotfix on the currently running base version,
downloads and installs it once it's baked long enough, and prunes old
versions in that hotfix train — but never reboots. A successful install
just leaves a `.automatic-pending-reboot-<hostname>` marker for
`--reboot-pending` to pick up.

`--reboot-pending` is the only thing that ever reboots. Each device with
a marker is in one of two phases:

- **Not yet sent**: is *now* inside today's
  `[PANOS_AUTOMATIC_REBOOT_WINDOW_START, +PANOS_AUTOMATIC_REBOOT_WINDOW_LENGTH)`?
  If not — too early, or the window's already closed — nothing happens,
  and the marker is left for a later invocation to check again, including
  tomorrow's window if today's has passed. If it is in-window, it
  re-verifies live against the device (not just because the marker
  exists) that a reboot is still actually pending, and sends the reboot
  if so.
- **Already sent, awaiting confirmation**: rather than trusting the
  reboot request being *accepted* as proof it actually happened,
  `--reboot-pending` checks `show system info` on later invocations
  (not window-gated — confirming isn't a new action) and only clears the
  marker once both the running version matches what was expected *and*
  uptime has reset to less than the time since the reboot was sent
  (proof a reboot genuinely occurred, not just a device that happened to
  already be on the right version). Unconfirmed for over an hour prints
  a persistent warning instead of silently giving up or sending a second
  reboot at a device that might still be mid-cycle.

**Invoke it more often than the window is long** — a coarser cadence
than the window risks missing it entirely some days if the two don't
happen to line up (e.g. an hourly cron firing on the hour would never
catch a `02:17`-start window at all).

---

## 9. Updating the Virtual Environment

### In-place upgrade

Pull the latest script changes, then upgrade dependencies in the existing venv:

```bash
git pull
source .venv/bin/activate
pip install -r requirements.txt --upgrade
deactivate
```

### Fresh venv

If the in-place upgrade runs into dependency conflicts, rebuild the venv from scratch:

```bash
deactivate 2>/dev/null || true
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
deactivate
```

Existing `.env`, `.devices`, and `.apikey-*` files are untouched by either approach — they live outside `.venv/`.
