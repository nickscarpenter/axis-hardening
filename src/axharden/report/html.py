"""Self-contained HTML report: one file, inline CSS, no scripts, no external resources (a CSP forbids them).

Kept short on purpose: each camera shows its problems and the changes made; everything else is folded
into <details> sections. Status cells use symbols as well as colour so they read in mono print.
"""

from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path

from .. import GUIDE_REF, __version__
from ..audit import CameraResult, write_private
from ..catalog import LEVELS, Catalog
from ..evaluate import COMPLIANT, ERROR, INFO, NA, NON_COMPLIANT, NOT_SUPPORTED, ControlResult, compliance_pct

SYMBOL = {
    COMPLIANT: ("✔", "ok", "Compliant"),
    NON_COMPLIANT: ("✘", "bad", "Non-compliant"),
    NOT_SUPPORTED: ("—", "na", "Not supported on this firmware/model"),
    NA: ("—", "na", "Not applicable"),
    ERROR: ("!", "err", "Could not be read"),
    INFO: ("i", "info", "Information / manual check"),
}
CHANGE_LABEL = {"verified": ("✔", "ok", "Changed and verified"), "failed": ("✘", "bad", "Failed"),
                "skipped": ("—", "na", "Not attempted"), "applied": ("?", "err", "Written, not verified")}
LEVEL_TITLE = {"default": "Default protection", "basic": "Basic hardening", "extended": "Extended hardening",
               "legacy": "Legacy hardening"}
KIND_TITLE = {"audit": "Audit (read-only)", "apply": "Hardening changes", "rollback": "Rollback (undo)"}

CSS = """
:root{--ok:#1e7b34;--okb:#e3f1e6;--bad:#b3261e;--badb:#f8e0de;--err:#9a5b00;--errb:#fbecd5;--info:#1f5fa8;--infob:#e2ecf7;--na:#6b6b6b;--line:#d0d0d0}
*{box-sizing:border-box}
body{font:13px/1.45 system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1d1d1d;margin:0}
main{max-width:1100px;margin:0 auto;padding:20px 24px 40px}
h1{font-size:20px;margin:28px 0 6px}h2{font-size:15px;margin:16px 0 4px}h1:first-child{margin-top:0}
.cls{background:#1d1d1d;color:#fff;text-align:center;font-weight:700;letter-spacing:.05em;padding:3px;font-size:12px}
table{border-collapse:collapse;width:100%;margin:4px 0 8px}
th,td{border:1px solid var(--line);padding:3px 6px;vertical-align:top;text-align:left;font-size:12px}
th{background:#2b2b2b;color:#fff;font-weight:600}
.kv{display:grid;grid-template-columns:max-content 1fr max-content 1fr;gap:2px 14px;margin:4px 0 8px;font-size:12px}
.kv b{color:#444;font-weight:600}
.s{text-align:center;font-weight:700;width:24px}
.ok{color:var(--ok);background:var(--okb)}.bad{color:var(--bad);background:var(--badb)}
.err{color:var(--err);background:var(--errb)}.info{color:var(--info);background:var(--infob)}.na{color:var(--na)}
tr.lvl td{background:#ececec;font-weight:700}
.matrix th.cam{writing-mode:vertical-rl;transform:rotate(180deg);white-space:nowrap;padding:6px 2px;height:110px;width:30px}
.muted{color:#555;font-size:12px}
.warn{border-left:4px solid var(--bad);background:var(--badb);padding:6px 10px;margin:6px 0}
.note{border-left:4px solid var(--info);background:var(--infob);padding:6px 10px;margin:6px 0}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin:6px 0 10px}
.stat{border:1px solid var(--line);border-radius:6px;padding:6px 12px;min-width:120px}
.stat b{display:block;font-size:20px}
.legend span{margin-right:12px;white-space:nowrap}
code{font-family:Consolas,monospace;font-size:11px;word-break:break-all}
details{margin:4px 0 8px}summary{cursor:pointer;color:#1f5fa8}
section.cam{border-top:2px solid #2b2b2b;margin-top:22px;padding-top:4px}
footer{margin-top:30px;font-size:11px;color:#555;border-top:1px solid var(--line);padding-top:6px}
@page{size:A4;margin:14mm 12mm 16mm}
@page{@bottom-right{content:"Page " counter(page) " of " counter(pages);font:9px sans-serif}}
@media print{main{max-width:none;padding:0}section.cam{break-before:page}tr{break-inside:avoid}
 body{-webkit-print-color-adjust:exact;print-color-adjust:exact}summary{color:#1d1d1d}}
"""


def e(text: object) -> str:
    return escape("" if text is None else str(text))


def cell(status: str, title: str = "") -> str:
    s, cls, text = SYMBOL.get(status, ("?", "", status))
    return f'<td class="s {cls}" title="{e(title or text)}">{s}</td>'


def _name(c: CameraResult) -> str:
    return c.camera.get("name") or c.camera["host"]


def _final(c: CameraResult) -> list[ControlResult]:
    return c.after or c.results


def _kv(pairs: list[tuple[str, object]]) -> str:
    return '<div class="kv">' + "".join(f"<b>{e(k)}</b><span>{e(v)}</span>" for k, v in pairs if v not in (None, "")) + "</div>"


def build_html(meta: dict, cams: list[CameraResult], catalog: Catalog, out: Path, classification: str = "",
               title: str = "AXIS camera hardening report", log_entries: list[dict] | None = None) -> Path:
    run_id = meta["run_id"]
    cls_bar = f'<div class="cls">{e(classification)}</div>' if classification else ""
    parts = [
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>{e(title)} - {e(run_id)}</title><style>{CSS}</style></head><body>", cls_bar, "<main>",
        _summary(meta, cams, catalog, title),
        _matrix(cams, catalog, meta),
        "".join(_camera(c, catalog, meta) for c in cams),
        _exceptions(meta, cams, catalog),
        _appendix(catalog, log_entries or []),
        f"<footer>axharden {e(__version__)} &bull; run {e(run_id)} &bull; {e(GUIDE_REF)} &bull; "
        "credentials were held in memory only and appear nowhere in this report</footer>",
        "</main>", cls_bar, "</body></html>",
    ]
    write_private(out, "".join(parts))
    return out


def _summary(meta: dict, cams: list[CameraResult], catalog: Catalog, title: str) -> str:
    kind = meta.get("kind", "audit")
    sites = sorted({c.camera.get("site") for c in cams if c.camera.get("site")})
    tls = ("DISABLED (--insecure)" if meta.get("insecure_tls") else
           (f"CA bundle {meta['ca_bundle']}" if meta.get("ca_bundle") else "system trust store"))
    html = f"<h1>{e(title)}</h1>" + _kv([
        ("Type", KIND_TITLE.get(kind, kind) + (" - SIMULATED, no real camera touched" if meta.get("simulated") else "")),
        ("Run", meta["run_id"]), ("Operator", meta.get("operator") or "(not given)"),
        ("Date", (meta.get("started") or "")[:16].replace("T", " ")), ("Profile", meta.get("profile", "")),
        ("Site(s)", ", ".join(sites)), ("TLS verification", tls),
        ("Rollback of", meta.get("rollback_of")), ("Based on audit", meta.get("audit_run")),
        ("Confirmed by", meta.get("confirmed_by")),
    ])
    if meta.get("insecure_tls"):
        html += '<div class="warn">TLS certificate verification was off for this run (--insecure).</div>'
    reachable = [c for c in cams if c.reachable]
    before = compliance_pct([r for c in reachable for r in c.results])
    after = compliance_pct([r for c in reachable for r in _final(c)])
    stats = [("Cameras", len(cams)), ("Checked", len(reachable)),
             ("Not checked", sum(not c.reachable for c in cams))]
    if kind == "audit":
        stats.append(("Compliance", "n/a" if before is None else f"{before:.0f}%"))
        stats.append(("Problems", sum(r.status == NON_COMPLIANT for c in reachable for r in c.results)))
    else:
        done = Counter(ch.get("status") for c in cams for ch in c.changes if "writes" in ch)
        stats.append(("Compliance", "n/a" if before is None else
                      f"{before:.0f}% → {after:.0f}%" if after is not None else f"{before:.0f}%"))
        stats += [("Changes verified", done.get("verified", 0)), ("Failed", done.get("failed", 0)),
                  ("Not attempted", done.get("skipped", 0))]
    html += '<div class="stats">' + "".join(f'<div class="stat"><b>{e(v)}</b>{e(k)}</div>' for k, v in stats) + "</div>"
    pf = meta.get("password_findings") or {}
    for g in pf.get("shared_groups") or []:
        html += f'<div class="warn"><b>Common password</b> (guide p.31): {e(", ".join(g))}</div>'
    if pf.get("weak"):
        html += f'<div class="warn"><b>Password under 8 characters</b> (guide p.16): {e(", ".join(pf["weak"]))}</div>'
    if any(ch.get("requires_reboot") and ch.get("status") == "verified" for c in cams for ch in c.changes):
        html += ('<div class="note">Some changes (TLS ciphers) take effect only after the camera restarts its HTTPS '
                 "service. Reboot those cameras at a convenient time.</div>")
    return html


def _matrix(cams: list[CameraResult], catalog: Catalog, meta: dict) -> str:
    ids = [cid for cid in meta.get("control_ids", []) if cid in catalog.by_id]
    reachable = [c for c in cams if c.reachable]
    if not reachable or not ids:
        return ""
    after = any(c.after for c in reachable)
    html = ("<h1>Overview</h1><p class=\"legend muted\">" +
            "".join(f'<span><b class="{c}">&nbsp;{s}&nbsp;</b> {e(t)}</span>' for st, (s, c, t) in SYMBOL.items() if st != NA) +
            ("<br>Showing the state <b>after</b> changes." if after else "") + "</p>")
    for start in range(0, len(reachable), 20):
        chunk = reachable[start:start + 20]
        html += '<table class="matrix"><tr><th>Control</th>' + "".join(
            f'<th class="cam">{e(_name(c))}</th>' for c in chunk) + "</tr>"
        for level in LEVELS:
            level_ids = [i for i in ids if catalog.by_id[i].level == level]
            if not level_ids:
                continue
            html += f'<tr class="lvl"><td colspan="{1 + len(chunk)}">{e(LEVEL_TITLE[level])}</td></tr>'
            for cid in level_ids:
                html += f"<tr><td>{e(cid)} {e(catalog.by_id[cid].title)}</td>"
                for cam in chunk:
                    r = next((x for x in _final(cam) if x.id == cid), None)
                    html += cell(r.status if r else NA, r.detail if r else "")
                html += "</tr>"
        html += "</table>"
    return html


def _found(observed: dict) -> str:
    return "; ".join(f"{k.replace('root.', '')}={v}" for k, v in observed.items()
                     if not isinstance(v, (list, dict)))[:240]


def _control_table(results: list[ControlResult], catalog: Catalog) -> str:
    html = "<table><tr><th></th><th>Control</th><th>p.</th><th>Found</th><th>Detail</th></tr>"
    for r in results:
        ctl = catalog.by_id.get(r.id)
        html += (f"<tr>{cell(r.status)}<td>{e(r.id)} {e(ctl.title if ctl else '')}</td>"
                 f"<td>{e(ctl.guide_page if ctl else '')}</td><td><code>{e(_found(r.observed))}</code></td>"
                 f"<td>{e(r.detail)}</td></tr>")
    return html + "</table>"


def _camera(cam: CameraResult, catalog: Catalog, meta: dict) -> str:
    c, d = cam.camera, cam.device
    cert = next((r.observed.get("issuer") for r in cam.results if r.id == "AX-C-004" and r.observed), "")
    final = _final(cam)
    p_before = compliance_pct(cam.results) if cam.results else None
    p_after = compliance_pct(cam.after) if cam.after else None
    score = "" if p_before is None else (f"{p_before:.0f}%" + (f" → {p_after:.0f}%" if p_after is not None else ""))
    html = f'<section class="cam"><h1>{e(_name(cam))}</h1>' + _kv([
        ("IP", c["host"] + (f":{c['port']}" if c.get("port") else "")), ("Site", c.get("site", "")),
        ("Model", d.get("ProdFullName") or d.get("ProdNbr", "")), ("AXIS OS", d.get("Version", "")),
        ("Serial", d.get("SerialNumber", "")), ("MAC", d.get("MAC", "")),
        ("Compliance", score), ("Certificate", cert), ("Notes", c.get("notes", "")),
    ])
    if cam.status not in ("OK",):
        html += f'<div class="warn"><b>{e(cam.status)}</b> {e(cam.error)}</div>'

    real_changes = [ch for ch in cam.changes if "writes" in ch]
    if real_changes:
        html += "<h2>Changes</h2><table><tr><th></th><th>Control</th><th>Setting</th><th>Before</th><th>After</th><th>Result</th></tr>"
        for ch in real_changes:
            sym, klass, label = CHANGE_LABEL.get(ch["status"], ("?", "", ch["status"]))
            for i, w in enumerate(ch["writes"]):
                first = i == 0
                n = len(ch["writes"])
                lead = (f'<td class="s {klass}" rowspan="{n}" title="{e(label)}">{sym}</td>'
                        f'<td rowspan="{n}">{e(ch["control_id"])} {e(ch["title"])}</td>') if first else ""
                tail = f'<td rowspan="{n}">{e(label)}. {e(ch.get("detail") or "")}</td>' if first else ""
                html += (f"<tr>{lead}<td><code>{e(w['name'].replace('root.', ''))}</code></td>"
                         f"<td><code>{e(w['old'])}</code></td><td><code>{e(w['new'])}</code></td>{tail}</tr>")
        html += "</table>"

    problems = [r for r in final if r.status in (NON_COMPLIANT, ERROR)]
    if final:
        label = "Remaining problems" if cam.after else "Problems"
        html += f"<h2>{label} ({len(problems)})</h2>"
        html += _control_table(problems, catalog) if problems else '<p class="muted">None.</p>'
        others = [r for r in final if r not in problems]
        html += (f"<details><summary>Show the other {len(others)} controls (compliant, information, not supported)"
                 f"</summary>{_control_table(others, catalog)}</details>")
    return html + "</section>"


def _exceptions(meta: dict, cams: list[CameraResult], catalog: Catalog) -> str:
    failed = [c for c in cams if c.status != "OK"]
    manual = sorted({r.id for c in cams for r in _final(c) if r.status == INFO})
    if not failed and not manual:
        return ""
    html = '<section class="cam"><h1>Follow-up</h1>'
    if failed:
        html += "<h2>Cameras needing attention</h2><table><tr><th>Camera</th><th>Status</th><th>Reason</th></tr>"
        html += "".join(f"<tr><td>{e(_name(c))}</td><td>{e(c.status)}</td><td>{e(c.error)}</td></tr>" for c in failed)
        html += "</table>"
    if manual:
        html += "<h2>Manual checks and extended hardening</h2><ul>" + "".join(
            f"<li>{e(cid)} {e(catalog.by_id[cid].title)} (guide p.{catalog.by_id[cid].guide_page})</li>"
            for cid in manual if cid in catalog.by_id) + "</ul>"
    return html + "</section>"


def _appendix(catalog: Catalog, log_entries: list[dict]) -> str:
    html = ('<section class="cam"><h1>Reference</h1><details><summary>Control catalog '
            f"({len(catalog.controls)} controls, SHA-256 {e(catalog.sha256[:16])}...)</summary>"
            "<table><tr><th>ID</th><th>Title</th><th>Guide section</th><th>p.</th><th>CSC</th>"
            "<th>Hardened value / check</th><th>Verified on</th></tr>")
    for ctl in catalog.controls:
        html += (f"<tr><td>{e(ctl.id)}</td><td>{e(ctl.title)}</td><td>{e(ctl.guide_section)}</td>"
                 f"<td>{ctl.guide_page}</td><td>{e(' '.join(ctl.csc))}</td>"
                 f"<td><code>{e(ctl.hardened_summary.replace('root.', ''))}</code></td>"
                 f"<td>{e(', '.join(ctl.verified_on) or 'no')}</td></tr>")
    html += "</table></details>"
    if log_entries:
        html += (f"<details><summary>Audit log extract ({len(log_entries)} entries for this run)</summary>"
                 "<table><tr><th>Time</th><th>Event</th><th>Camera</th><th>Control</th><th>Setting</th>"
                 "<th>Old</th><th>New</th><th>Result</th><th>Hash</th></tr>")
        for le in log_entries:
            html += (f"<tr><td>{e(le.get('ts', '')[11:19])}</td><td>{e(le.get('event'))}</td><td>{e(le.get('camera', ''))}</td>"
                     f"<td>{e(le.get('control', ''))}</td><td><code>{e(str(le.get('setting', '')).replace('root.', ''))}</code></td>"
                     f"<td><code>{e(le.get('old', ''))}</code></td><td><code>{e(le.get('new', ''))}</code></td>"
                     f"<td>{e(le.get('result', ''))}</td><td><code>{e(le.get('hash', '')[:12])}</code></td></tr>")
        html += "</table></details>"
    return html + "</section>"
