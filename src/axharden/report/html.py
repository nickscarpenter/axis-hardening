"""Self-contained HTML report: one file, inline CSS, no scripts, no external resources (a CSP forbids them).
Status cells use symbols as well as colour so the matrix reads in mono print. Print to PDF from any browser."""

from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path

from .. import GUIDE_REF, __version__
from ..audit import CameraResult, write_private
from ..catalog import LEVELS, Catalog
from ..evaluate import COMPLIANT, ERROR, INFO, NA, NON_COMPLIANT, NOT_SUPPORTED, compliance_pct

SYMBOL = {
    COMPLIANT: ("✔", "ok", "Compliant"),
    NON_COMPLIANT: ("✘", "bad", "Non-compliant"),
    NOT_SUPPORTED: ("—", "na", "Not supported on this firmware/model"),
    NA: ("—", "na", "Not applicable"),
    ERROR: ("!", "err", "Error reading"),
    INFO: ("i", "info", "Information / manual check"),
}
LEVEL_TITLE = {"default": "Default protection", "basic": "Basic hardening", "extended": "Extended hardening",
               "legacy": "Legacy hardening"}

CSS = """
:root{--ok:#1e7b34;--okb:#e3f1e6;--bad:#b3261e;--badb:#f8e0de;--err:#9a5b00;--errb:#fbecd5;--info:#1f5fa8;--infob:#e2ecf7;--na:#6b6b6b;--line:#c8c8c8}
*{box-sizing:border-box}
body{font:13px/1.45 system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1d1d1d;margin:0;background:#fff}
main{max-width:1180px;margin:0 auto;padding:24px 28px 48px}
h1{font-size:22px;margin:32px 0 8px}h2{font-size:16px;margin:22px 0 6px}h1:first-child{margin-top:0}
.cls{background:#1d1d1d;color:#fff;text-align:center;font-weight:700;letter-spacing:.05em;padding:4px;font-size:12px}
table{border-collapse:collapse;width:100%;margin:6px 0 10px}
th,td{border:1px solid var(--line);padding:3px 6px;vertical-align:top;text-align:left}
th{background:#2b2b2b;color:#fff;font-weight:600;font-size:12px}
td{font-size:12px}
table.kv th{background:#f0f0f0;color:#1d1d1d;width:190px}
.s{text-align:center;font-weight:700;width:26px}
.ok{color:var(--ok);background:var(--okb)}.bad{color:var(--bad);background:var(--badb)}
.err{color:var(--err);background:var(--errb)}.info{color:var(--info);background:var(--infob)}.na{color:var(--na)}
tr.lvl td{background:#e4e4e4;font-weight:700}
.matrix td.s,.matrix th.cam{width:52px}
.matrix th.cam{writing-mode:vertical-rl;transform:rotate(180deg);white-space:nowrap;text-align:left;padding:6px 2px;height:120px}
.muted{color:#555;font-size:12px}
.warn{border-left:4px solid var(--bad);background:var(--badb);padding:8px 12px;margin:10px 0}
.legend span{display:inline-block;margin-right:14px}
.legend b{display:inline-block;width:18px;text-align:center}
code{font-family:Consolas,monospace;font-size:11.5px;word-break:break-all}
section.cam{break-before:page}
footer{margin-top:40px;font-size:11px;color:#555;border-top:1px solid var(--line);padding-top:6px}
@page{size:A4;margin:14mm 12mm 16mm}
@page{@bottom-right{content:"Page " counter(page) " of " counter(pages);font:9px sans-serif}}
@media print{main{max-width:none;padding:0}.cls{position:running(cls)}h1{break-after:avoid}tr{break-inside:avoid}
 body{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""


def e(text: object) -> str:
    return escape("" if text is None else str(text))


def cell(status: str, title: str = "") -> str:
    s, cls, text = SYMBOL.get(status, ("?", "", status))
    return f'<td class="s {cls}" title="{e(title or text)}">{s}</td>'


def _kv(rows: list[tuple[str, object]]) -> str:
    return '<table class="kv">' + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows) + "</table>"


def build_html(meta: dict, cams: list[CameraResult], catalog: Catalog, out: Path,
               classification: str = "", title: str = "AXIS camera hardening report") -> Path:
    run_id = meta["run_id"]
    cls_bar = f'<div class="cls">{e(classification)}</div>' if classification else ""
    parts = [
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        # No network, no scripts: everything is inline.
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>{e(title)} - {e(run_id)}</title><style>{CSS}</style></head><body>",
        cls_bar, "<main>",
        _cover(meta, cams, catalog, title),
        _summary(meta, cams),
        _matrix(cams, catalog, meta),
        "".join(_camera(c, catalog) for c in cams),
        _exceptions(meta, cams, catalog),
        _appendix(catalog),
        f"<footer>axharden {e(__version__)} &bull; run {e(run_id)} &bull; {e(GUIDE_REF)}</footer>",
        "</main>", cls_bar, "</body></html>",
    ]
    write_private(out, "".join(parts))
    return out


def _cover(meta: dict, cams: list[CameraResult], catalog: Catalog, title: str) -> str:
    sites = sorted({c.camera.get("site") or "(no site)" for c in cams}) or ["(none)"]
    tls = ("DISABLED (--insecure)" if meta.get("insecure_tls") else
           (f"CA bundle {meta['ca_bundle']}" if meta.get("ca_bundle") else "System trust store"))
    rows = [("Site(s)", ", ".join(sites)), ("Run ID", meta["run_id"]), ("Started", meta.get("started", "")),
            ("Finished", meta.get("finished", "")), ("Operator", meta.get("operator") or "(not given)"),
            ("Profile", meta.get("profile", "")), ("Cameras", len(cams)),
            ("Tool version", f"axharden {meta.get('tool_version', __version__)}"),
            ("Catalog SHA-256", meta.get("catalog_sha256", catalog.sha256)),
            ("Reference", meta.get("guide", GUIDE_REF)), ("TLS verification", tls)]
    if meta.get("simulated"):
        rows.append(("Mode", "SIMULATED from recorded fixtures - not a live audit"))
    html = f"<h1>{e(title)}</h1><p class=\"muted\">Audit of AXIS OS hardening controls (read-only)</p>" + _kv(rows)
    if meta.get("insecure_tls"):
        html += ('<div class="warn"><b>Warning:</b> TLS certificate verification was disabled for this run '
                 "(--insecure). Camera identity was not cryptographically verified.</div>")
    return html


def _legend(include_na: bool = False) -> str:
    items = [(s, v) for s, v in SYMBOL.items() if include_na or s != NA]
    return '<p class="legend muted">' + "".join(
        f'<span><b class="{c}">{sy}</b> {e(t)}</span>' for _, (sy, c, t) in items) + "</p>"


def _summary(meta: dict, cams: list[CameraResult]) -> str:
    reachable = [c for c in cams if c.reachable]
    results = [r for c in reachable for r in c.results]
    counts = Counter(r.status for r in results)
    pct = compliance_pct(results)
    html = "<h1>Executive summary</h1>" + _kv([
        ("Cameras in scope", len(cams)), ("Reachable", len(reachable)),
        ("Failed (see Exceptions)", sum(not c.reachable for c in cams)),
        ("Out of scope (AXIS OS < 10.0)", sum(c.status == "OUT_OF_SCOPE" for c in cams)),
        ("Overall compliance (scored controls)", "n/a" if pct is None else f"{pct:.0f}%"),
        ("Changes applied", "0 (read-only audit)"),
    ])
    html += "<h2>Results across all reachable cameras</h2><table><tr><th></th><th>Status</th><th>Count</th></tr>"
    for st, (_, _, text) in SYMBOL.items():
        html += f"<tr>{cell(st)}<td>{e(text)}</td><td>{counts.get(st, 0)}</td></tr>"
    html += ("</table><p class=\"muted\">Compliance % counts only controls scored compliant or non-compliant. "
             "Not supported, N/A, information and error results are excluded.</p>")
    pf = meta.get("password_findings") or {}
    if pf.get("shared_groups") or pf.get("weak"):
        html += "<h2>Password warnings</h2>"
        for g in pf.get("shared_groups") or []:
            html += f'<div class="warn"><b>Common password</b> (guide p.31) shared by: {e(", ".join(g))}</div>'
        if pf.get("weak"):
            html += f'<div class="warn"><b>Weak password</b> (under 8 characters, guide p.16): {e(", ".join(pf["weak"]))}</div>'
    html += ("<h2>Per-camera compliance</h2><table><tr><th>Camera</th><th>Site</th><th>Model</th><th>AXIS OS</th>"
             "<th>Status</th><th>Compliance</th><th>Non-compliant</th></tr>")
    for c in cams:
        p = compliance_pct(c.results) if c.reachable else None
        html += (f"<tr><td>{e(c.camera.get('name') or c.camera['host'])}</td><td>{e(c.camera.get('site', ''))}</td>"
                 f"<td>{e(c.device.get('ProdNbr', ''))}</td><td>{e(c.device.get('Version', ''))}</td>"
                 f"<td>{e(c.status)}</td><td>{'' if p is None else f'{p:.0f}%'}</td>"
                 f"<td>{sum(r.status == NON_COMPLIANT for r in c.results)}</td></tr>")
    return html + "</table>"


def _matrix(cams: list[CameraResult], catalog: Catalog, meta: dict) -> str:
    ids = [cid for cid in meta.get("control_ids", []) if cid in catalog.by_id]
    reachable = [c for c in cams if c.reachable]
    html = "<h1>Compliance matrix</h1>"
    if not reachable:
        return html + "<p>No reachable cameras.</p>"
    html += _legend()
    per_table = 16
    for start in range(0, len(reachable), per_table):
        chunk = reachable[start:start + per_table]
        html += '<table class="matrix"><tr><th>ID</th><th>Control</th><th>p.</th>' + "".join(
            f'<th class="cam">{e(c.camera.get("name") or c.camera["host"])}</th>' for c in chunk) + "</tr>"
        for level in LEVELS:
            level_ids = [i for i in ids if catalog.by_id[i].level == level]
            if not level_ids:
                continue
            html += f'<tr class="lvl"><td colspan="{3 + len(chunk)}">{e(LEVEL_TITLE[level])}</td></tr>'
            for cid in level_ids:
                ctl = catalog.by_id[cid]
                html += f"<tr><td>{e(cid)}</td><td>{e(ctl.title)}</td><td>{ctl.guide_page}</td>"
                for cam in chunk:
                    r = next((x for x in cam.results if x.id == cid), None)
                    html += cell(r.status if r else NA, r.detail if r else "")
                html += "</tr>"
        html += "</table>"
    return html


def _found(observed: dict) -> str:
    return "; ".join(f"{k.replace('root.', '')}={v}" for k, v in observed.items()
                     if not isinstance(v, (list, dict)))[:300]


def _camera(cam: CameraResult, catalog: Catalog) -> str:
    c, d = cam.camera, cam.device
    cert = next((r.observed.get("issuer") for r in cam.results if r.id == "AX-C-004" and r.observed), "")
    html = f'<section class="cam"><h1>Camera: {e(c.get("name") or c["host"])}</h1>' + _kv([
        ("IP / host", c["host"] + (f":{c['port']}" if c.get("port") else "")), ("Site", c.get("site", "")),
        ("Model", d.get("ProdFullName") or d.get("ProdNbr", "")), ("Serial", d.get("SerialNumber", "")),
        ("MAC", d.get("MAC", "")), ("AXIS OS", d.get("Version", "")), ("Status", cam.status),
        ("Authentication", f"{cam.auth_scheme} over {cam.scheme}" if cam.auth_scheme else ""),
        ("Certificate issuer", cert or ""), ("Notes", c.get("notes", "")),
    ])
    if cam.error:
        html += f'<div class="warn"><b>{e(cam.status)}:</b> {e(cam.error)}</div>'
    if cam.results:
        html += ("<table><tr><th></th><th>ID</th><th>Control</th><th>p.</th><th>CSC</th><th>Found</th>"
                 "<th>Result / detail</th></tr>")
        for r in cam.results:
            ctl = catalog.by_id.get(r.id)
            html += (f"<tr>{cell(r.status)}<td>{e(r.id)}</td><td>{e(ctl.title if ctl else '')}</td>"
                     f"<td>{e(ctl.guide_page if ctl else '')}</td><td>{e(' '.join(ctl.csc) if ctl else '')}</td>"
                     f"<td><code>{e(_found(r.observed))}</code></td><td><b>{e(r.status)}</b> {e(r.detail)}</td></tr>")
        html += "</table>"
    return html + "</section>"


def _exceptions(meta: dict, cams: list[CameraResult], catalog: Catalog) -> str:
    html = '<section class="cam"><h1>Exceptions and warnings</h1>'
    failed = [c for c in cams if not c.reachable or c.status == "OUT_OF_SCOPE"]
    if failed:
        html += "<h2>Cameras not fully audited</h2><table><tr><th>Camera</th><th>Status</th><th>Reason</th></tr>"
        html += "".join(f"<tr><td>{e(c.camera.get('name') or c.camera['host'])}</td><td>{e(c.status)}</td>"
                        f"<td>{e(c.error)}</td></tr>" for c in failed) + "</table>"
    errs = [(c, r) for c in cams for r in c.results if r.status == ERROR]
    if errs:
        html += "<h2>Controls that could not be read</h2><table><tr><th>Camera</th><th>Control</th><th>Error</th></tr>"
        html += "".join(f"<tr><td>{e(c.camera.get('name') or c.camera['host'])}</td><td>{e(r.id)}</td>"
                        f"<td>{e(r.detail)}</td></tr>" for c, r in errs) + "</table>"
    if meta.get("insecure_tls"):
        html += '<h2>TLS verification disabled</h2><p>This run used --insecure: camera certificates were not verified.</p>'
    manual = sorted({r.id for c in cams for r in c.results if r.status == INFO})
    if manual:
        html += "<h2>Items for manual review or extended hardening</h2><ul>" + "".join(
            f"<li><b>{e(cid)}</b> {e(catalog.by_id[cid].title)} (guide p.{catalog.by_id[cid].guide_page})</li>"
            for cid in manual if cid in catalog.by_id) + "</ul>"
    html += ("<h2>Operator notes</h2><p>Credentials were read from the operator's inventory file for this run and "
             "held in memory only. If that file contains passwords it is plain text: keep it on encrypted media or "
             "leave the password column blank and enter passwords when prompted. No credentials appear in this report.</p>")
    return html + "</section>"


def _appendix(catalog: Catalog) -> str:
    html = ('<section class="cam"><h1>Appendix: control catalog</h1>'
            f'<p class="muted">Catalog SHA-256 <code>{e(catalog.sha256)}</code>. Source: {e(GUIDE_REF)}. '
            "Verified = parameter names confirmed against a real camera.</p>"
            "<table><tr><th>ID</th><th>Title</th><th>Guide section</th><th>p.</th><th>CSC</th>"
            "<th>Hardened value / check</th><th>Verified on</th></tr>")
    for ctl in catalog.controls:
        html += (f"<tr><td>{e(ctl.id)}</td><td>{e(ctl.title)}</td><td>{e(ctl.guide_section)}</td>"
                 f"<td>{ctl.guide_page}</td><td>{e(' '.join(ctl.csc))}</td>"
                 f"<td><code>{e(ctl.hardened_summary.replace('root.', ''))}</code></td>"
                 f"<td>{e(', '.join(ctl.verified_on) or 'no')}</td></tr>")
    return html + "</table></section>"
