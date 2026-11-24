# Security notes

## Runtime dependencies

Pinned with SHA-256 hashes in `requirements.lock` (install with `--require-hashes`). The build
produces a CycloneDX SBOM at `dist/sbom.cdx.json`.

| Package | Why |
|---|---|
| `requests` | HTTPS client with Digest/Basic auth for VAPIX |
| `urllib3`, `idna`, `charset-normalizer`, `certifi` | dependencies of `requests` (`certifi` supplies the default CA bundle; use `--ca-bundle` for a site CA) |
| `openpyxl` (+ `et-xmlfile`) | reading `.xlsx` inventories |
| `PyYAML` | the control catalog and profiles (`yaml.safe_load` only) |

Everything else is the Python standard library: `csv`, `argparse`, `ssl`, `json`, `html`, `xml.etree`, `logging`.
The report is plain HTML with no PDF library. Test-only: `pytest`, `responses`. Build-only: `pyinstaller`, `cyclonedx-bom`, `pip-tools`.

## Design rules

- **No network calls except to camera IPs in the inventory.** No telemetry, update checks or CDN assets.
  The HTML report carries a Content-Security-Policy that blocks all external loads and scripts.
  Proxy environment variables are ignored for camera traffic.
- **Credentials in memory only.** They are read from the inventory each run and never written to
  snapshots, reports, logs or exceptions. `Credential.__repr__` masks the password, pickling is refused,
  and a redacting log filter masks registered passwords, `Authorization` headers, Digest responses and
  URL credentials.
- **Never Basic auth over HTTP.** The tool refuses and reports it instead.
- **Never retry 401/403**, so the camera's own brute-force protection is never triggered.
- **Output files** are created owner-only (`0600`; best effort on Windows NTFS, so keep `output\` on a
  protected volume).
- **No `eval`, `pickle` or `yaml.load`.** All camera-supplied text is HTML-escaped in reports.
- **TLS:** verification is on by default. `--insecure` is explicit, warned about on screen and recorded in
  the report. The certificate check (AX-C-004) parses the camera certificate with the standard library's
  `ssl._ssl._test_decode_cert`, a private but long-standing API, to avoid adding a crypto dependency.

## Reporting a problem

Raise it with the tool maintainer; do not include real inventories or camera dumps that have not been sanitised.
