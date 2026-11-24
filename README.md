# axharden: AXIS camera hardening audit

Portable, offline tool that checks AXIS cameras (AXIS OS 10.0 and later) against the
**AXIS OS Hardening guide T10177717 (2026-07)** and produces an HTML report, plus CSV and JSON.

This build is **read-only** (phase 1). It never changes camera settings. `plan`, `apply` and
`rollback` arrive in phase 2.

## 1. Install (offline)

Use either:

- **Windows, no Python needed:** copy `axharden-win64\` to the machine and run `axharden.exe`.
- **Source folder (Windows or Linux, Python 3.11+):**
  ```
  python -m venv .venv
  .venv\Scripts\python -m pip install --no-index --find-links wheels -r requirements.lock
  axharden.cmd --version          (Linux: ./axharden.sh --version)
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

## 4. Verify the catalog against a reference camera

```
axharden discover --inventory cameras.xlsx --target 10.0.0.21 --insecure
```

This dumps the camera's settings and API list to `output\discover\...`, lists catalog settings missing on
that firmware, and writes a sanitised `fixture.json` that can be added to `tests\fixtures\`.

## 5. Try it without cameras

```
axharden audit --simulate tests\fixtures
```

## Development

```
python -m venv .venv && .venv\Scripts\pip install -e .[test]
.venv\Scripts\python -m pytest
```

Build the offline deliverables (needs internet on the build machine): `build_offline.ps1` / `build_offline.sh`.
