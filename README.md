# panos-tool

A command-line tool for managing PAN-OS firmware and GlobalProtect client software on Palo Alto firewalls via the XML API. Tested on PAN-OS 11.2.x and 12.1.x. Work in progress.

No Panorama support — written for environments with individual firewalls managed directly.

## What it does

**Firmware lifecycle**
- List downloaded versions, check for newer hotfixes, download, install, reboot
- Schedule a reboot at a specific time (`--reboot-at-time HH:MM`) — with or without a preceding install
- Bulk delete: by exact version, by wildcard pattern, or by age threshold (`--delete-lt-version`)
- Show which version is staged to activate on the next reboot (`--show-pending`)
- Unattended maintenance mode (`--automatic` / `--reboot-pending`) for cron-based fleet upkeep

**GlobalProtect client**
- List available client versions, download, activate

**Utilities**
- Refresh the software catalog from Palo Alto's update servers
- Refresh licenses
- Fetch and cache API keys per device/user

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.sample .env
chmod 600 .env
# Edit .env — set PANOS_USERNAME and PANOS_PASSWORD

./panos-tool.py --list-downloaded-versions firewall.example.com
```

Runs against multiple devices with a comma-separated list or a `.devices` file:

```bash
./panos-tool.py --list-downloaded-versions fw1.example.com,fw2.example.com
./panos-tool.py --list-downloaded-versions --all-devices
```

## Security notes

- API keys are sent via `X-PAN-KEY` header, not URL query parameters
- Credential files (`.env`, `.apikey-*`) are created and checked at `0600` — the script refuses to run if they're wider
- TLS verification is on by default; `--allow-unverified-tls` to opt out

## Documentation

See [setup.md](setup.md) for full setup instructions, credential resolution order, cron examples, and the `--automatic` maintenance workflow.

See [flows.md](flows.md) for lifecycle diagrams.

## Requirements

Python 3.11+, `requests`, `python-dotenv`, `defusedxml`. See `requirements.txt`.

## License

GPL-3.0 — see [LICENSE](LICENSE).
