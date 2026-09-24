# PAN-OS Firmware Cleanup — Automatic Maintenance Flows

Lifecycle diagrams for the two unattended-maintenance flags, `--automatic`
and `--reboot-pending` — see [setup.md](setup.md#unattended-automatic-maintenance---automatic----reboot-pending)
for the cron/`.env` setup. Each is a per-device loop; a device that hits a
`Skip`/`Next device` outcome just waits for the next invocation.

## `--automatic` (daily)

```mermaid
flowchart TD
    A["Start: for each device"] --> B{"Marker file exists?"}
    B -->|yes| B1(["Skip — reboot already pending,<br/>waiting for --reboot-pending"]) --> Z["Next device"]
    B -->|no| C{"Today == PANOS_AUTOMATIC_WEEKDAY?"}
    C -->|no| C1(["Skip — nothing to do today"]) --> Z
    C -->|yes| D{"Reachable on :443?"}
    D -->|no| D1(["Skip device"]) --> Z
    D -->|yes| E{"Resolve API key<br/>(stored or fetch)"}
    E -->|fail| E1(["Skip device"]) --> Z
    E -->|ok| F["refresh_software_list<br/>(request system software check)"]
    F --> G["get_available_firmware<br/>(request system software info)"]
    G -->|fail| G1(["Skip device"]) --> Z
    G -->|ok| H["filter_malformed_versions<br/>warn + drop unparseable entries"]
    H --> I{"Current version known?"}
    I -->|no| I1(["Skip device"]) --> Z
    I -->|yes| J["find_next_hotfix<br/>same major.minor.maintenance,<br/>highest hotfix > current"]
    J --> K{"Newer hotfix found?"}
    K -->|no| L["Log: nothing newer"] --> P
    K -->|yes| M{"Baked >= PANOS_AUTOMATIC_MIN_AGE_DAYS?<br/>(released-on, UTC)"}
    M -->|no| M1["Log: found but not baked yet"] --> P
    M -->|yes| N{"Already downloaded?"}
    N -->|no| N1["download_firmware<br/>(poll job to completion)"] --> O
    N -->|yes| O["install_firmware<br/>(poll job to completion)"]
    O -->|fail| O1["Log error"] --> P
    O -->|ok| O2["installed_version = target<br/>re-fetch version list"] --> P
    P["prune_hotfix_train<br/>same hotfix train only, keep<br/>PANOS_AUTOMATIC_KEEP_VERSIONS,<br/>protects current + just-installed +<br/>base versions with dependents"]
    P --> Q{"Install succeeded this run?"}
    Q -->|yes| Q1["mark_pending_reboot<br/>(empty marker: reboot owed)"] --> Z
    Q -->|no| Z
```

## `--reboot-pending` (frequent, two-phase)

```mermaid
flowchart TD
    A["Start: for each device"] --> B{"Marker file exists?"}
    B -->|no| B1(["Nothing to do"]) --> Z["Next device"]
    B -->|yes| C{"acquire_automatic_lock"}
    C -->|fail| C1(["Another invocation is<br/>handling this device — skip"]) --> Z
    C -->|ok| D["read_pending_reboot_state"]
    D --> E{"State recorded<br/>(sent_at + expected_version)?"}

    E -->|"yes (Phase 2)"| F{"Reachable + API key ok?"}
    F -->|no| F1(["Log: will check next run"]) --> R
    F -->|yes| G["reboot_confirmed:<br/>show system info —<br/>sw-version == expected AND<br/>uptime has wrapped"]
    G -->|confirmed| G1["Clear marker"] --> R
    G -->|not confirmed| H{"Elapsed > 1h grace?<br/>(REBOOT_CONFIRMATION_GRACE_SECONDS)"}
    H -->|yes| H1(["WARNING: unconfirmed,<br/>check manually — marker kept"]) --> R
    H -->|no| H2(["Log: not confirmed yet,<br/>check next run"]) --> R

    E -->|"no (Phase 1)"| I{"Within today's reboot window?<br/>(WINDOW_START / WINDOW_LENGTH)"}
    I -->|no| I1(["Log: wait for window"]) --> R
    I -->|yes| J{"Reachable + API key ok?"}
    J -->|no| J1(["Skip, retry next run"]) --> R
    J -->|yes| K["get_swm_status<br/>(debug swm status)"]
    K -->|fail| K1(["Skip, retry next run"]) --> R
    K -->|ok| L{"find_pending_change_version:<br/>PENDING-CHANGE partition?"}
    L -->|no| L1["Clear stale marker"] --> R
    L -->|yes| M["reboot_device<br/>(request restart system)"]
    M -->|success| M1["mark_pending_reboot<br/>sent_at=now,<br/>expected_version=pending"] --> R
    M -->|failure| R

    R["release_automatic_lock"] --> Z
```

**Note on finding #32 (Low, open):** Phase 2's grace-period warning
(`H`/`H1` above) is only reached once a device answers `F` (reachable +
authenticated). A device unreachable past the 1-hour grace period prints
the routine `F1` "will check again next run" line instead, on every
invocation, rather than the persistent `H1` warning — reachability is
arguably the more accurate diagnosis in that case, but it means a long
outage never produces the one-time "still not confirmed" warning.
