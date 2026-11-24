# AXIS Camera Hardening Tool — Project Specification

> Build brief for Claude Code. Read this whole file before writing code.
> Working name: **axharden**
> Source of truth for controls: **AXIS OS Hardening guide, doc T10177717, 2026-07 (M71.3)**. Keep a copy at `docs/AXIS_OS_Hardening_Guide_T10177717.pdf`. Page numbers below refer to that PDF.

---

## 1. Purpose

A portable, offline tool that lets an engineer on a secure (air-gapped / CNI) network:

1. **Load** a list of AXIS devices (IP addresses and credentials) from a CSV/XLSX file at the start of each run, keeping credentials in memory only.
2. **Interrogate** each device through the AXIS VAPIX API and record which hardening controls are **ON / OFF / NOT SUPPORTED / ERROR**.
3. **Apply** (enable or disable) a selected set of hardening controls, on one camera or in bulk.
4. **Verify** each change by reading it back after writing it.
5. **Report**: generate a self-contained HTML report (printable to PDF from a browser) showing, per camera, what was found, what was changed and the final state, with each control traced to its section of the Axis guide.

---

## 2. Hard constraints

| Constraint | Requirement |
|---|---|
| **Offline** | Makes no internet calls at runtime: no telemetry, no update checks, no CDN fonts or assets. The only network traffic is to the camera IPs in the inventory. |
| **Portable** | Runs from a USB stick or a copied folder with no installer and no admin rights. Ships as either (a) a PyInstaller one-folder build for Windows, or (b) a source folder with `wheels/` installable with `pip install --no-index --find-links wheels`. A build script produces both. |
| **Platform** | Windows 10/11 is the primary target; must also run on Linux. Python 3.11+. |
| **Minimal dependencies** | Only well-known, auditable packages (§3). Pinned with hashes in `requirements.lock`. |
| **Credentials in memory only** | Credentials are read from the operator's inventory file at the start of each run and held in memory only. The tool never writes them anywhere (no vault, cache, snapshot or output file), never logs them and never shows them in reports. Protecting the inventory file itself is the operator's job (§5.3). |
| **Safe by default** | Read-only unless the user explicitly chooses "apply". A dry-run preview is always shown before any write. |
| **Auditable** | Every API write is logged (camera, control, old value, new value, result, timestamp, operator) to an append-only, hash-chained log. |

---

## 3. Tech stack

- **Language:** Python 3.11+
- **HTTP:** `requests`. Choose the authentication scheme from the camera's `WWW-Authenticate` header:
  - AXIS OS ≤ 12 defaults to **Digest** (`HTTPDigestAuth`).
  - AXIS OS 13+ defaults to **HTTPS-only with Basic** (guide p.5). Basic is allowed **only over HTTPS**. Never send Basic over plain HTTP; refuse and report it instead.
- **TLS:** HTTPS by default, with a user-supplied CA bundle or per-camera certificate pinning. A `--insecure` flag allows self-signed or 802.1AR device-ID certificates that aren't in the trust store; it is warned about loudly and recorded in the report.
- **Concurrency:** `ThreadPoolExecutor`, default 8 workers, but **at most 1 in-flight request per camera** (see §7.5, brute-force protection).
- **Import:** `csv` (stdlib) and `openpyxl`
- **Config / catalog:** YAML via `PyYAML`, `safe_load` only
- **Report:** plain HTML generated with the standard library (inline CSS, no scripts, no external resources). Chosen over a PDF library to keep the tool small (drops `reportlab` + `pillow`).
- **CLI:** `typer` (or `argparse` to reduce dependencies)
- **GUI (phase 3, optional):** `tkinter`
- **Tests:** `pytest` and `responses`
- **Packaging:** `PyInstaller`, plus `build_offline.ps1` / `build_offline.sh`

---

## 4. Project layout

```
axharden/
├── CLAUDE.md
├── README.md                      # operator quick-start
├── SECURITY.md                    # dependency justification + SBOM pointer
├── docs/AXIS_OS_Hardening_Guide_T10177717.pdf
├── requirements.in / requirements.lock
├── build_offline.ps1 / build_offline.sh
├── catalog/
│   ├── hardening_controls.yaml    # generated from §6 of this file
│   └── profiles/                  # audit-only.yaml, basic-safe.yaml, basic-full.yaml
├── templates/inventory_template.csv / .xlsx
├── axharden.cmd / axharden.sh     # launchers for the source-folder deliverable
├── packaging/axharden_entry.py    # PyInstaller entry point
├── src/axharden/
│   ├── __main__.py, cli.py        # argparse CLI
│   ├── inventory.py               # load + validate list; credentials held in memory only
│   ├── vapix/
│   │   ├── client.py              # session, auth negotiation, TLS, per-camera throttle
│   │   ├── params.py              # param.cgi list, case-insensitive ParamTree
│   │   ├── device.py              # basicdeviceinfo, apidiscovery, model, serial, MAC
│   │   └── handlers.py            # non-param controls and CHECK readers
│   ├── catalog.py                 # catalog + profile loading, schema validation
│   ├── evaluate.py                # status rules (pure logic)
│   ├── version.py                 # AXIS OS version parsing/comparison
│   ├── audit.py                   # batch runner, snapshots, --simulate replay
│   ├── discover.py                # reference-camera dump, catalog diff, sanitised fixture
│   ├── apply.py                   # phase 2
│   ├── report/html.py, export.py  # HTML report, CSV/JSON export
│   ├── logging_setup.py           # redacting logger
│   └── gui/ (phase 3)
├── tests/ (+ fixtures/ sanitised discover dumps)
└── output/                        # runtime only, git-ignored
```

---

## 5. Inventory (loaded fresh every run)

There is no import step and no stored inventory. Every command that talks to cameras takes `--inventory <file>`, reads it, holds it in memory for that run, and discards it on exit.

### 5.1 Input formats
CSV or XLSX, with a header row (header names are case-insensitive).

| Column | Required | Notes |
|---|---|---|
| `ip` | ✔ | IPv4, IPv6 or hostname, with an optional `:port` |
| `username` | ✔ | Admin account |
| `password` | | If blank, the tool prompts for it at run time (hidden input, once per distinct username, reused for every blank row with that username). Lets operators keep a file with no passwords in it. |
| `name` | | Friendly name / camera ID |
| `site` | | Groups cameras in the report |
| `protocol` | | `https` (default) or `http` |
| `profile` | | Overrides the global profile for this camera |
| `ports` | | Unused network ports for AX-B-021/022, e.g. `5;6;7` (phase 3). Never guessed. |
| `notes` | | Free text, shown in the report |

### 5.2 Behaviour
- Validate every row (bad IP, missing field, duplicate IP) and report all errors before doing anything.
- The file is opened read-only and never modified, copied or deleted by the tool.
- `axharden inventory template` writes blank CSV/XLSX templates.
- `axharden inventory check --inventory <file>` validates the file and prints it with passwords masked. It makes no network calls.
- **Common-password check** (guide p.31, "Common password"): warn if several cameras share the same password, and show that warning in the report. Compare salted hashes in memory only; the report names the cameras, never the password or a hash.
- Weak-password flag: warn if a password has fewer than 8 characters (guide p.16).
- Password rotation is **out of scope**: it would mean writing new passwords to disk, which this design avoids.

### 5.3 Credential handling
- Credentials live only in process memory, in a `Credential` object whose `__repr__`/`__str__` mask the password. They never appear in exceptions, logs, run snapshots, reports or the audit log.
- Run snapshots (`output/runs/<run-id>/`) record the camera IP/name and settings only, so `rollback` re-reads credentials from `--inventory` like any other command.
- No passphrase, no vault file, no `cryptography` dependency.
- **Operator responsibility (stated in README and in the report's exceptions section):** the inventory file is plain text if it contains passwords. Keep it on encrypted media (e.g. BitLocker To Go / an encrypted USB stick) or leave the password column blank and type passwords at the prompt.

---

## 6. Hardening control catalog

Generate `catalog/hardening_controls.yaml` from the tables below. Two kinds of control:

- **APPLY** controls: the tool can read *and* set them. These come directly from the guide's **"Basic hardening via VAPIX API"** table (pp.32–34).
- **CHECK** controls: the tool **reads and reports only**. They come from the rest of the guide (default protection, extended hardening), where the guide gives a setting path but no hardening VAPIX call, or where the right value depends on the site (NTP servers, syslog target, firewall rules, certificates).

Parameter paths are normalised to the `root.` prefix. The guide writes some without it, and VAPIX accepts both. Each entry has a `verified_on` list ("model firmware") filled in only once its names have been confirmed against a real camera with `axharden discover` (§7.4). The guide warns (p.31) that an error from a call can simply mean the feature was removed in that AXIS OS version. Treat a **missing parameter as NOT SUPPORTED, not as a failure**.

**Parameter presence wins over the guide's version notes.** If a parameter exists on the camera it is evaluated, whatever `removed_in` says; `removed_in` / `introduced_in` only explain why a parameter is missing. (Real example: `System.EditCgi` is still present on 10.12.252 although the guide says the script editor was removed in 10.11.) Handler controls with `introduced_in` above the device version are skipped as NOT_SUPPORTED without a request.

Statuses: `COMPLIANT`, `NON_COMPLIANT`, `NOT_SUPPORTED`, `N/A`, `ERROR`, plus `INFO` for report-only checks, advisory results and items needing a manual check. Compliance % counts only COMPLIANT and NON_COMPLIANT.

**Confirmed on AXIS M4216-LV, AXIS OS 10.12.252** (discover, 2026-11-24): `PreventDoSAttack` (capital S) incl. `ActivatePasswordThrottling`; `RTSP.ProtViewer`, `System.BoaProtViewer`, `PTZ.BoaProtPTZOperator`; `RemoteService.Enabled` values `yes|no|oneclick`; audio is `root.Audio.A<n>.Enabled`; the SD slot is `root.Storage.S<n>.Enabled` where `DiskID=SD_DISK` (no `SDDiskEnabled`); `Network.HTTP.AuthenticationPolicy`; `Network.RTSPS.Enabled`; `Network.Filter.*`; `SNMP.Enabled/V1/V2c/V3`; `Time.NTP.Server` (`0.0.0.0` = none); signed video is `root.Image.I<n>.MPEG.SignedVideo.Enabled`; 802.1X is `root.Network.Interface.I0.dot1x.Enabled/Status`. `applications/config.cgi` returns **404** on 10.12 (AX-B-019/020 NOT_SUPPORTED there). `pwdgrp.cgi?action=get` lists real accounts in `digusers`.

### 6.0 Firmware scope: AXIS OS 10.0 and later

All cameras in scope run **AXIS OS 10.0 or later**. The catalog, profiles and test fixtures cover that range only.

- `min_supported_os: "10.0"` in config. A camera reporting a lower version is still audited (read-only) and reported, but marked **OUT_OF_SCOPE**: no plan is generated for it and `apply` refuses to write to it.
- Controls whose feature was removed before 10.0 are not in the catalog (AX-B-007 ARP/Ping, removed in 7.10; Telnet, < 5.50). Their IDs stay reserved so the numbering never changes meaning.
- Features introduced before 10.0 (brute-force protection 7.30, HTTPS 7.20, RTSPS 7.40, web-UI disable 9.50, SD disable 9.80) are always available in scope, so they carry no `introduced_in`.
- Version-limited controls inside the range, which `removed_in` / `introduced_in` must handle:

| Feature | Present on | Control |
|---|---|---|
| UPnP NATTraversal | 10.0 – 10.11 | AX-B-002 (second param) |
| Script editor (`EditCgi`) | 10.0 – 10.10 | AX-B-013 |
| FTP | 10.0 – 11.0 | AX-B-006 |
| TLS 1.0/1.1 switches | 10.0 – 11.x | AX-B-010 |
| IP address filter | 10.0 – 11.8 | AX-C-009 |
| HTTP server-header hide | 10.6+ | AX-B-017 |
| 802.1AR device-ID cert replaces self-signed | 10.10+ | AX-C-004 |
| UART debug disabled by default | 10.11+ | reported from version only |
| NTS | 11.1+ | AX-C-005 |
| Network port PoE/traffic disable | 11.2+ | AX-B-021, AX-B-022 |
| OAuth 2.0 / OpenID | 11.6+ | AX-C-015 |
| Host-based firewall | 11.9+ | AX-C-009 |
| Anonymous basic-device-info switch | 11.11+ | AX-B-025 |
| UPnP/SSDP off by default; TLS 1.0/1.1 removed; ACAP signing on by default | 12.0+ | AX-B-002, AX-B-010, AX-B-020 |
| WS-Discovery off by default; ZeroConf not required | 12.1+ | AX-B-003, AX-B-008 |
| Default HTTPS-only + Basic auth; ACAP signing mandatory; signed video on by default | 13.0+ | §3, AX-B-020, AX-C-011 |

- Authentication within scope: 10.x – 12.x default to Digest; 13.x defaults to HTTPS-only with Basic (§3).
- A feature that is **removed** for the camera's version (`removed_in` ≤ version) is reported as `NOT_SUPPORTED` and counts as compliant, because the insecure option no longer exists. A feature **not yet introduced** (`introduced_in` > version) is `NOT_SUPPORTED` and is listed in the report as "upgrade AXIS OS to get this control".

### 6.1 Control schema

```yaml
- id: AX-B-001
  title: Disable Bonjour discovery protocol
  guide_section: "Disable unused services/functions > Network discovery protocols"
  guide_page: 18
  csc: ["4"]
  level: basic            # default | basic | extended | legacy (legacy = removed somewhere in 10.x–11.x)
  kind: apply             # apply | check
  method: param           # param | handler
  params:                 # one or more; ALL must match for COMPLIANT
    - name: root.Network.Bonjour.Enabled
      hardened: "no"
      optional: false     # true = skip this param if missing (e.g. NATTraversal on ≥ 10.12)
  compare: equals         # equals | subset (AX-B-011 ciphers)
  handler: null
  removed_in: null        # AXIS OS version where the feature no longer exists (compared numerically: 10.6 < 10.12)
  introduced_in: null     # only for versions above 10.0
  disruptive: false       # could cut off tool / VMS access
  requires_reboot: false
  warning: null           # shown in plan + report
  verified: false
```

Value comparison is **case-insensitive** (`yes`/`Yes`, `on`/`On`). Treat `ActivatePasswordThrottling` on/off and `AccessLog` On/Off the same way.

### 6.2 APPLY controls — Basic hardening via VAPIX (guide pp.32–34)

| ID | Control | Parameter(s) / call → hardened value | Notes |
|---|---|---|---|
| AX-B-001 | Disable Bonjour | `root.Network.Bonjour.Enabled=no` | p.18 |
| AX-B-002 | Disable UPnP | `root.Network.UPnP.Enabled=no` **and** `root.Network.UPnP.NATTraversal.Enabled=no` | NATTraversal exists only on 10.0–10.11 (`removed_in: 10.12`, `optional: true`). UPnP/SSDP are off by default from 12.0. |
| AX-B-003 | Disable WS-Discovery | `root.WebService.DiscoveryMode.Discoverable=no` | Off by default from 12.1. ⚠ Do this **after** the camera has been added to the VMS. |
| AX-B-004 | Disable O3C (one-click cloud) | `root.RemoteService.Enabled=no` | |
| AX-B-005 | Disable SSH | `root.Network.SSH.Enabled=no` | p.20 |
| AX-B-006 | Disable FTP | `root.Network.FTP.Enabled=no` | Legacy: present on 10.0–11.0, `removed_in: 11.1` |
| AX-B-007 | *(retired)* Disable ARP/Ping IP config | — | Removed in 7.10, so never present on 10.0+. Not in the catalog; ID reserved. |
| AX-B-008 | Disable ZeroConf | `root.Network.ZeroConf.Enabled=no` | Not required from 12.1 (link-local fallback), so report it as informational there |
| AX-B-009 | **HTTPS only** | `root.System.BoaGroupPolicy.admin=https`, `.operator=https`, `.viewer=https` | **DISRUPTIVE**: switch the tool session to HTTPS before writing. Also enables HSTS (p.30). |
| AX-B-010 | TLS 1.2/1.3 only | `root.HTTPS.AllowTLS1=no`, `root.HTTPS.AllowTLS11=no` | Legacy: present on 10.0–11.x, `removed_in: 12.0` (counts as compliant there by design) |
| AX-B-011 | Secure TLS 1.2 ciphers | `root.HTTPS.Ciphers=ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305` | **Requires reboot / HTTPS restart** (p.23). Compliant = the device list contains **only** ciphers from this set. |
| AX-B-012 | Brute-force protection | `root.System.PreventDoSAttack.ActivatePasswordThrottling=on`, `DoSBlockingPeriod=10`, `DoSPageCount=20`, `DoSPageInterval=1`, `DoSSiteCount=20`, `DoSSiteInterval=1` | Available on all in-scope versions; on by default from 11.5, so expect NON_COMPLIANT on 10.x–11.4. The guide's web path writes `PreventDosAttack`, so confirm the exact case with `discover`. |
| AX-B-013 | Disable script editor | `root.System.EditCgi=no` | Legacy: present on 10.0–10.10, `removed_in: 10.11` |
| AX-B-014 | Enable access log | `root.System.AccessLog=On` | p.29 |
| AX-B-015 | ONVIF replay attack protection | `root.WebService.UsernameToken.ReplayAttackProtection=yes` | On by default (p.5) |
| AX-B-016 | **Disable web interface** | `root.System.WebInterfaceDisabled=yes` | Available on all in-scope versions. **DISRUPTIVE for people, not for the API**: confirm that VAPIX still works afterwards. Off in `basic-safe`. |
| AX-B-017 | Hide HTTP/OpenSSL server header | `root.System.HTTPServerTokens=no` | Introduced in 10.6. ⚠ The guide (p.19) says this can break vulnerability scanners, so it is opt-in. |
| AX-B-018 | Disable anonymous viewer/PTZ | `root.Network.RTSP.ProtViewer=password`, `root.System.BoaProtViewer=password`, `root.PTZ.BoaProtPTZOperator=password` | PTZ parameter only on PTZ models, so missing = N/A |
| AX-B-019 | Block root-privilege ACAPs | handler: `GET /axis-cgi/applications/config.cgi?action=set&name=AllowRoot&value=false` | Read via `action=get` / `list`; confirm with `discover` |
| AX-B-020 | Block unsigned ACAPs | handler: `GET /axis-cgi/applications/config.cgi?action=set&name=AllowUnsigned&value=false` | Enforced by default in 12.0+ and mandatory in 13.0 |
| AX-B-021 | Disable PoE on unused ports | handler: `/axis-cgi/nvr/poe/setportmode.cgi?port=X&enabled=no` | `introduced_in: 11.2`. Multi-port devices only (e.g. S3008). The guide misprints this as `enabld=`, so use the correct spelling and confirm it. **Ports to disable come from the inventory/profile and are never guessed.** |
| AX-B-022 | Disable traffic on unused ports | handler: `POST /axis-cgi/network_settings.cgi` `{"apiVersion":"1.17","method":"setDeviceConfiguration","params":{"deviceName":"eth1.N","staticState":"down"}}` | `introduced_in: 11.2`. Same rules as AX-B-021. **DISRUPTIVE** if the wrong port is chosen. |
| AX-B-023 | Disable SD card slot (if unused) | `root.Storage.S<n>.Enabled=no` for the storage entry with `DiskID=SD_DISK` (an explicit `*SDDiskEnabled` param is used if a firmware has one) | Available on all in-scope versions. Opt-in, because some sites record to SD. |
| AX-B-024 | Disable audio (if unused) | `root.Audio.A*.Enabled=no` (every audio config) | Opt-in. No audio params = N/A. |
| AX-B-025 | Hide anonymous basic-device-info | handler: REST `PATCH /config/rest/basic-device-info/v2beta/allowAnonymous` body `{"data": false}` | `introduced_in: 11.11`, guide p.20. Opt-in (scanner impact). |

### 6.3 CHECK controls — read and report only

| ID | Check | How to read | Compliant when |
|---|---|---|---|
| AX-C-001 | AXIS OS version / track | `basicdeviceinfo.cgi` → `Version` | Report the version and track (10.x / 11.x / 12.x LTS or active). Below 10.0 → OUT_OF_SCOPE (§6.0). Also flag versions below a configurable site minimum (`min_axis_os` in config, default `10.0`, since there is no internet to check "latest"). |
| AX-C-002 | HTTP authentication policy | `root.Network.HTTP.AuthenticationPolicy` *(confirm)* | `digest`, or HTTPS-only with basic. Flag basic over HTTP (p.5). |
| AX-C-003 | HTTPS-only / HSTS in effect | Try HTTP:80 and expect a redirect or refusal | Same result as AX-B-009 |
| AX-C-004 | Certificate in use | TLS handshake → issuer | Flag self-signed (the factory default on 10.0–10.9). 802.1AR device ID (factory default from 10.10) = OK. CA-signed = best (p.24). |
| AX-C-005 | NTP/NTS configured | `root.Time.*` / time API | At least one server configured; ≥ 2 recommended; NTS noted (11.1+) |
| AX-C-006 | Remote syslog configured | syslog config / `root.RemoteSyslog.*` *(confirm)* | A target is configured. Report TLS on or off. |
| AX-C-007 | SNMP | `root.SNMP.*` | Off, **or** v3 only. Flag v1 or v2c (p.25). |
| AX-C-008 | RTSPS / SRTP | `root.Network.RTSPS.Enabled` *(confirm)* | Enabled (only if the VMS supports it, so a "No" here is advisory) |
| AX-C-009 | Firewall (11.9+) / IP filter (10.0–11.8) | Pick by version: firewall API on 11.9+, `root.Network.Filter.*` below | Enabled with a default `Drop` policy and rules present. **Never written by this tool** (lock-out risk). |
| AX-C-010 | IEEE 802.1X | 802.1X config | Report enabled or disabled |
| AX-C-011 | Signed video | `root.Image.*.SignedVideo.Enabled` *(confirm)* | Enabled (default from 13.0; on 10.x–12.x expect it off unless set). Model-dependent, so missing = N/A. |
| AX-C-012 | SD card encryption | Storage API | Encrypted, if an SD card is present |
| AX-C-013 | Installed ACAPs | `applications/list.cgi` | Report the list. Flag third-party and non-running apps. |
| AX-C-014 | User accounts | `pwdgrp.cgi?action=get` | Report count and roles. Flag "admin only, with no separate operator/viewer account" (p.16). |
| AX-C-015 | OAuth 2.0 / OpenID | OpenID config | Report only (11.6+) |
| AX-C-016 | Strict security mode | Report if the API exists | Report only (p.27) |
| AX-C-017 | LLDP/CDP | Network discovery settings | Report only. ⚠ Disabling can affect PoE negotiation (p.19). |
| AX-C-018 | Network filter log | `root.Network.Filter.Log.Enabled` | `yes`; otherwise INFO (advisory) |
| AX-C-019 | Common / weak password | From the inventory load (§5.2) | Unique and ≥ 8 characters |

### 6.4 Profiles (`catalog/profiles/`)

| Profile | Contents |
|---|---|
| `audit-only` | Every CHECK control and every APPLY control in **read** mode. The default for `audit`. |
| `basic-safe` | AX-B-001…006, 008…015, 018, 019, 020, plus the CHECKs. Includes the legacy controls (002 NATTraversal, 006, 010, 013); version gating makes them `NOT_SUPPORTED` on firmware where they were removed, so one profile fits all of 10.0+. **Excludes** web-interface disable, server-header hide, port shutdowns, SD/audio disable, and anon device-info. |
| `basic-full` | Equivalent to Axis's own ADM hardening file (guide p.34): `basic-safe` + AX-B-016 (web UI off) + AX-B-017. |
| ~~`legacy`~~ | Dropped. It existed for AXIS OS < 10, which is out of scope, and `basic-safe` already covers the 10.x–11.x legacy controls. |
| *custom* | Users can copy a profile and add or remove IDs. Port controls (AX-B-021/022) take a per-camera `ports:` list. |

---

## 7. Core workflows (CLI)

```
axharden inventory template
axharden inventory check --inventory cameras.xlsx               # validate, mask passwords, no network
axharden discover  --inventory cameras.xlsx --target 10.0.0.21  # dump the param tree + apidiscovery → verify the catalog
axharden audit     --inventory cameras.xlsx [--site X] [--profile audit-only]
axharden plan      --inventory cameras.xlsx --profile basic-safe [--site X]  # dry run
axharden apply     --inventory cameras.xlsx --profile basic-safe [--site X] [--controls AX-B-001,...] [--yes]
axharden rollback  --inventory cameras.xlsx --run <run-id> [--camera ip]
axharden report    --run <run-id> [--out report.pdf]            # no credentials needed
```

Every command that contacts cameras needs `--inventory`; `report` works from the saved run alone.

### 7.1 Audit
1. Read device info (`/axis-cgi/basicdeviceinfo.cgi`): model, serial, MAC, AXIS OS version and product type.
2. Fetch **all** parameters in one `param.cgi?action=list` call and cache them. Do not make one request per control.
3. Run the CHECK handlers.
4. Evaluate each control → `COMPLIANT`, `NON_COMPLIANT`, `NOT_SUPPORTED` (parameter missing; the reason comes from `removed_in`/`introduced_in`), `N/A` (e.g. no PTZ), `INFO` (report-only / advisory / manual) or `ERROR` (with the reason).
5. Snapshot every raw value read to `output/runs/<run-id>/<ip>.json` for evidence and rollback.

Unreachable cameras, authentication failures and TLS errors are recorded per camera and never stop the batch.

### 7.2 Apply
1. Always run an audit first.
2. The plan contains only controls where current ≠ hardened.
3. Show a table (camera × control × current → hardened) that flags `disruptive`, `requires_reboot` and `warning`.
4. Confirm interactively (or `--yes`, which is logged).
5. **Write order per camera:**
   1. all non-disruptive param changes, **batched into one `param.cgi?action=update&a=..&b=..` call** where possible
   2. ACAP config handlers
   3. AX-B-011 ciphers (reboot or HTTPS restart needed, so schedule it last or prompt)
   4. AX-B-009 HTTPS-only: confirm HTTPS works first, then write, then re-connect over HTTPS and verify
   5. AX-B-016 web-UI disable: then confirm VAPIX still responds
   6. port controls last, one at a time, with a reachability check after each
6. Read back every change; a mismatch is a failure.
7. If a camera becomes unreachable after a disruptive step, stop that camera, report it clearly, and do not retry in a loop.
8. Log every write to the audit log.

### 7.3 Rollback
Reapply the pre-change snapshot for the selected run, camera and controls. Logged the same way.

### 7.4 Discover (catalog verification)
Against a reference camera: dump `param.cgi?action=list` and `/axis-cgi/apidiscovery.cgi` to JSON, then diff them against the catalog. List the catalog parameters missing on this firmware and the parameter-name case differences (e.g. `PreventDosAttack` vs `PreventDoSAttack`). Offer to mark matched entries `verified: true` for that model and firmware.

### 7.5 Don't trip the camera's own brute-force protection
The guide's brute-force settings (p.33) block an IP for 10 s after 20 failed requests within the interval. So:
- **Never retry on 401/403.** Mark the camera `AUTH_FAILED` and move on.
- Allow at most one in-flight request per camera, with a small delay between requests (configurable, default 100 ms).
- Retry only on network timeouts or 5xx responses (max 2, with back-off).

---

## 8. Report (HTML)

One self-contained HTML file per run: inline CSS, no scripts, and a Content-Security-Policy that blocks all external loads. Print CSS gives A4 pages (with "page X of Y" where the browser supports `@page` margin boxes); print to PDF from any browser if a PDF is needed. All camera-supplied text is HTML-escaped.

1. **Cover:** title, site(s), date/time, operator name (prompted), run ID, profile, tool version, catalog hash, and the reference *"AXIS OS Hardening guide T10177717 (2026-07)"*
2. **Executive summary:** cameras in scope / reachable / failed; compliance % before → after; changes applied / failed / skipped; common-password warning
3. **Compliance matrix:** cameras × controls, grouped by guide level (Default / Basic / Extended / Legacy). Cells use symbols ✔ ✘ — (N/A or not supported) ! (error) as well as colour, so the matrix reads in mono print.
4. **Per-camera pages:** device info (model, serial, MAC, AXIS OS, IP, certificate issuer), then a table with control ID, title, guide page, CSC #, before, action, after and result
5. **Exceptions & warnings:** unreachable cameras, errors, controls not supported, `--insecure` use, items left for manual or extended work (firewall, PKI, 802.1X, syslog)
6. **Appendix:** control catalog (ID, title, guide section and page, CSC, hardened value) and the audit-log extract for the run

No passwords appear anywhere. The report shows the run ID in its footer and a configurable classification marking (`--classification`, e.g. "OFFICIAL-SENSITIVE") at top and bottom. The same data is also exported as CSV and JSON.

---

## 9. Security of the tool itself

- Redacting log formatter (passwords, `Authorization` headers, URL credentials).
- Never put credentials in URLs.
- `yaml.safe_load` only. No `eval` or `pickle`.
- Output files get restrictive permissions.
- Audit log is JSONL with each line hash-chained to the previous one (`prev_hash`).
- `SECURITY.md` lists every dependency and why it is needed. The build produces a CycloneDX SBOM.

---

## 10. Testing

- Unit tests: inventory parsing (incl. blank-password prompting), credential masking in `repr`/logs/exceptions/snapshots, catalog schema validation, AXIS OS version comparison, plan generation and write ordering.
- VAPIX mocked with `responses`: digest and basic auth, param list/update, 401 (must **not** retry), timeouts, missing parameters on old and new firmware, read-back mismatch, HTTP→HTTPS switch.
- Fixtures: sanitised `discover` dumps from real cameras (at least one AXIS OS 10.x LTS, one 11.x and one 12.x, plus 13.x when available). Ideally a 10.x dump below 10.11 to exercise the legacy params (`EditCgi`, NATTraversal). Version-gating tests must cover each boundary in §6.0, plus a < 10.0 camera to test OUT_OF_SCOPE.
- `--simulate` mode runs the whole pipeline against fixtures, with no cameras needed.

---

## 11. Build phases

1. **Phase 1 – Read-only:** inventory loading, VAPIX client, discover, audit, HTML/CSV/JSON report. *Built 2026-11-24; tested live on M4216-LV 10.12.252.*
2. **Phase 2 – Apply:** plan, dry-run, apply with verification, audit log, rollback. Profiles `basic-safe` → `basic-full`.
3. **Phase 3 – Extras:** tkinter GUI, port controls (AX-B-021/022), drift report comparing two runs.

---

## 12. Open items

- [x] Hardening guide supplied (T10177717, 2026-07)
- [x] AXIS OS versions in scope: **10.0 and later** (§6.0)
- [ ] Camera models in scope (PTZ? multi-port S3008? SD/audio use?)
- [x] Reference camera: AXIS M4216-LV, AXIS OS 10.12.252. Still need 11.x and 12.x reference cameras.
- [ ] Remote syslog, firewall (11.9+), OpenID and strict-security-mode read APIs: currently INFO / manual. Confirm the API endpoints on an 11.x/12.x camera.
- [ ] Are cameras already on HTTPS? Self-signed, 802.1AR or CA-issued certificates?
- [ ] Target OS on the secure system; Python allowed, or frozen .exe only?
- [ ] VMS in use (affects WS-Discovery, RTSPS and web-UI disable decisions)
- [ ] Report classification marking text and branding
- [x] Password rotation: out of scope (credentials are never written to disk, §5.3)
