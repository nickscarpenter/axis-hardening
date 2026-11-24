# axharden: AXIS camera hardening audit

Portable, offline tool that checks AXIS cameras (AXIS OS 10.0 and later) against the
**AXIS OS Hardening guide T10177717 (2026-07)** and produces an HTML report, plus CSV and JSON.

Checking is always read-only. Changing settings (`apply`, or *Fix problems...* in the GUI) always shows a
preview first, needs confirmation, reads every change back, logs it, and can be undone.

## Quick start for most people (Windows)

1. Copy the `axharden-win64` folder to the PC (USB stick is fine; nothing to install).
2. Double-click **`AXIS Hardening Check.exe`**.
3. **Step 1:** click *Choose camera list...* and pick the Excel/CSV list. No list yet? Click
   *Make a blank list...*, fill in one row per camera (`ip`, `username`; leave `password` empty and
   the program asks for it).
4. **Step 2:** type your name. If cameras come back as *Certificate problem*, choose
   *Accept the cameras' own certificates* and run again.
5. **Step 3:** click **Run check**, then **Open report**.
6. **Optional, fix problems:** click **Fix problems...**. Every change is listed with a tick box. Risky ones
   (HTTPS-only, web interface off) start unticked. Press **Apply**, and if anything goes wrong press
   **Undo last changes**.

Not sure what it does? *Tools > Try a demo* runs on recorded data, with no cameras needed. Checking
never changes a camera, and passwords are never saved. Double-click a camera in the
results to see what a problem means.

The rest of this page covers the command-line version, `axharden.exe`, in the same folder.

## 1. Install (offline)

Use either:

- **Windows, no Python needed:** copy `axharden-win64\` to the machine. It contains
  `AXIS Hardening Check.exe` (GUI) and `axharden.exe` (command line).
- **Source folder (Windows or Linux, Python 3.11+):**
  ```
  python -m venv .venv
  .venv\Scripts\python -m pip install --no-index --find-links wheels -r requirements.lock
  axharden.cmd --version          (Linux: ./axharden.sh --version)
  axharden-gui.cmd                 (opens the GUI; Linux: ./axharden.sh gui)
  ```

## 2. Prepare the camera list

```
axharden inventory template                       # writes templates\inventory_template.csv / .xlsx
```

| Column | Required | Notes |
|---|---|---|
| `ip` | yes | IPv4, IPv6 or hostname, optional `:port` |
| `username` | yes | admin account |
| `password` | no | **leave blank to be prompted** (once per username, hidden input) |
| `name`, `site`, `notes` | no | shown in the report; `site` also filters with `--site` |
| `protocol` | no | `https` (default) or `http` |
| `profile`, `ports` | no | reserved for phase 2/3 |

Check it without touching the network:

```
axharden inventory check --inventory cameras.xlsx
```

**Credentials are read from this file each run and held in memory only.** The tool never writes them
anywhere. If the file contains passwords it is plain text: keep it on encrypted media (for example
BitLocker To Go), or leave the password column blank and type passwords when prompted.

## 3. Audit

```
axharden audit --inventory cameras.xlsx --operator "J Smith" --classification "OFFICIAL-SENSITIVE"
```

Useful options:

| Option | Meaning |
|---|---|
| `--site A` | only cameras whose `site` is A |
| `--ca-bundle ca.pem` | trust your own CA for camera HTTPS |
| `--insecure` | accept certificates not in the trust store (e.g. the Axis 802.1AR device ID). Recorded in the report. |
| `--min-axis-os 11.11` | flag cameras below this version |
| `--workers 8` | cameras audited in parallel (always one request at a time per camera) |

Output goes to `output\runs\<run-id>\`:

- `report-<run-id>.html`: open in any browser; print to PDF if needed. Self-contained, no external files.
- `report-<run-id>.csv` / `.json`: the same results as data.
- `cameras\<ip>.json`: raw evidence per camera (settings read, probes, results). No credentials.

Regenerate a report later: `axharden report --run <run-id> [--classification ...]`.

### Result symbols

| | Meaning |
|---|---|
| ✔ | Compliant |
| ✘ | Non-compliant |
| — | Not supported on this firmware/model, or not applicable |
| i | Information or manual check |
| ! | Could not be read |

### Camera safety

The tool never retries a rejected login (401/403), so it never trips the camera's brute-force
protection. It sends one request at a time per camera with a 100 ms gap, never sends Basic auth over
plain HTTP, and never puts credentials in URLs. An unreachable camera or a failed login is recorded and
the batch continues.

## 4. Fix problems (apply) and undo (rollback)

```
axharden plan     --inventory cameras.xlsx --profile basic-safe     # dry run: shows every change
axharden apply    --inventory cameras.xlsx --profile basic-safe     # audit, preview, type YES, apply, verify
axharden apply    ... --controls AX-B-001,AX-B-014                  # only these controls
axharden rollback --inventory cameras.xlsx --run <apply-run-id>     # put the old values back
axharden log verify                                                 # check the audit log is untampered
```

Profiles: `basic-safe` (default; leaves out web-interface disable, server-header hide, SD/audio and port
controls) and `basic-full` (adds web interface off and hidden server header, matching Axis's own hardening file).

Per camera the tool writes ordinary settings in one batch, then ACAP/REST settings, then the cipher list
(takes effect after a reboot), then HTTPS-only (only after proving HTTPS works; it then reconnects over
HTTPS), then web interface off (then checks the API still answers). Every change is read back. If a camera
stops answering after a risky step, work on that camera stops and it is reported as `LOST_CONTACT`.
Every write is recorded in `outputudit_log.jsonl`, where each line is hash-chained to the one before.

## 5. Verify the catalog against a reference camera

```
axharden discover --inventory cameras.xlsx --target 10.0.0.21 --insecure
```

This dumps the camera's settings and API list to `output\discover\...`, lists catalog settings missing on
that firmware, and writes a sanitised `fixture.json` that can be added to `tests\fixtures\`.

## 6. Try it without cameras

```
axharden audit --simulate catalog\demo
axharden apply --simulate catalog\demo --yes     # changes only the in-memory demo cameras
```

## Development

```
python -m venv .venv && .venv\Scripts\pip install -e .[test]
.venv\Scripts\python -m pytest
```

Build the offline deliverables (needs internet on the build machine): `build_offline.ps1` / `build_offline.sh`.
