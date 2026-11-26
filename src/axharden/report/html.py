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
from ..evaluate import (COMPLIANT, ERROR, INFO, NA, NON_COMPLIANT, NOT_SUPPORTED, ControlResult, baseline_view,
                        compliance_pct)

SYMBOL = {
    COMPLIANT: ("✔", "ok", "Compliant"),
    NON_COMPLIANT: ("✘", "bad", "Non-compliant"),
    NOT_SUPPORTED: ("—", "na", "Not supported on this firmware/model"),
    NA: ("—", "na", "Not applicable"),
    ERROR: ("!", "err", "Could not be read"),
    INFO: ("i", "info", "Information"),
}
CHANGE_LABEL = {"verified": ("✔", "ok", "Changed and verified"), "failed": ("✘", "bad", "Failed"),
                "skipped": ("—", "na", "Not attempted"), "applied": ("?", "err", "Written, not verified")}
LEVEL_TITLE = {"default": "Default protection", "basic": "Basic hardening", "extended": "Extended hardening",
               "legacy": "Legacy hardening"}
# Traffic Light Protocol 2.0 (FIRST): label colours on black, and what each marking allows
TLP = {
    "TLP:RED": ("#FF2B2B", "For the named recipients only. Do not share further."),
    "TLP:AMBER+STRICT": ("#FFC000", "Share only within your own organisation, on a need-to-know basis."),
    "TLP:AMBER": ("#FFC000", "Share only within your organisation and its clients, on a need-to-know basis."),
    "TLP:GREEN": ("#33FF00", "Share within your community, but not publicly."),
    "TLP:CLEAR": ("#FFFFFF", "No limit on sharing."),
}
MATRIX_COLS = 8          # cameras per overview table (wider sets get several tables)


def tlp_label(text: str) -> str | None:
    """'tlp green', 'TLP:Amber+Strict', 'red' -> canonical 'TLP:...' label, else None."""
    t = (text or "").strip().upper().replace(" ", "").replace("_", "")
    t = t.removeprefix("TLP:").removeprefix("TLP")
    t = {"WHITE": "CLEAR", "AMBERSTRICT": "AMBER+STRICT"}.get(t, t)
    return f"TLP:{t}" if f"TLP:{t}" in TLP else None


def marking_bar(classification: str) -> str:
    if not classification:
        return ""
    label = tlp_label(classification)
    if label is None:
        return f'<div class="cls">{e(classification)}</div>'
    colour, meaning = TLP[label]
    return (f'<div class="cls tlp"><span style="color:{colour}">{e(label)}</span>'
            f'<small>{e(meaning)}</small></div>')


KIND_TITLE = {"audit": "Audit (read-only)", "apply": "Hardening changes", "rollback": "Rollback (undo)",
              "accounts": "User accounts created", "accounts-undo": "User accounts removed (undo)",
              "restart": "Camera restarts"}

CSS = """
:root{--ok:#1e7b34;--okb:#e3f1e6;--bad:#b3261e;--badb:#f8e0de;--err:#9a5b00;--errb:#fbecd5;--info:#1f5fa8;--infob:#e2ecf7;--na:#6b6b6b;--line:#d0d0d0}
*{box-sizing:border-box}
body{font:13px/1.45 system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1d1d1d;margin:0}
main{max-width:1100px;margin:0 auto;padding:20px 24px 40px}
h1{font-size:20px;margin:28px 0 6px}h2{font-size:15px;margin:16px 0 4px}h1:first-child{margin-top:0}
.cls{background:#1d1d1d;color:#fff;text-align:center;font-weight:700;letter-spacing:.05em;padding:3px;font-size:12px}
.cls.tlp{background:#000;padding:4px 8px}.cls.tlp span{font-size:13px;letter-spacing:.08em}
.cls.tlp small{font-weight:400;letter-spacing:0;margin-left:12px;color:#ddd}
table{border-collapse:collapse;width:100%;margin:4px 0 8px}
th,td{border:1px solid var(--line);padding:3px 6px;vertical-align:top;text-align:left;font-size:12px}
th{background:#2b2b2b;color:#fff;font-weight:600}
.kv{display:grid;grid-template-columns:max-content 1fr max-content 1fr;gap:2px 14px;margin:4px 0 8px;font-size:12px}
.kv b{color:#444;font-weight:600}
.s{text-align:center;font-weight:700;width:24px}
.ok{color:var(--ok);background:var(--okb)}.bad{color:var(--bad);background:var(--badb)}
.err{color:var(--err);background:var(--errb)}.info{color:var(--info);background:var(--infob)}.na{color:var(--na)}
tr.lvl td{background:#ececec;font-weight:700}
.matrix{table-layout:fixed}
.matrix th{vertical-align:bottom;padding:6px 8px}
.matrix th.cam{width:96px;text-align:center;font-size:11px;font-weight:600;line-height:1.25;overflow-wrap:anywhere}
.matrix td{padding:4px 8px}.matrix td.s{width:auto;font-size:13px}
.matrix tr:not(.lvl):hover td{background-image:linear-gradient(rgba(0,0,0,.04),rgba(0,0,0,.04))}
.matrix .cid{color:#555;font-family:Consolas,monospace;font-size:11px;margin-right:6px}
.muted{color:#555;font-size:12px}
.warn{border-left:4px solid var(--bad);background:var(--badb);padding:6px 10px;margin:6px 0}
.note{border-left:4px solid var(--info);background:var(--infob);padding:6px 10px;margin:6px 0}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin:6px 0 10px}
.stat{border:1px solid var(--line);border-radius:6px;padding:6px 12px;min-width:120px}
.stat b{display:block;font-size:20px}
.legend span{margin-right:12px;white-space:nowrap}
code{font-family:Consolas,monospace;font-size:11px;word-break:break-all}
details{margin:4px 0 8px}summary{cursor:pointer;color:#1f5fa8}
.fu th:nth-child(1){width:28%}.fu th:nth-child(2){width:4%}.fu th:nth-child(3){width:22%}
.ctl th:nth-child(2){width:30%}.ctl th:nth-child(4){width:24%}.ctl th:nth-child(5){width:18%}
.raw{margin-top:2px;font-size:11px;color:#777;word-break:break-word}
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


def _customer(c: CameraResult) -> str:
    return c.camera.get("customer") or c.camera.get("site") or ""   # "site" in runs saved by older versions


def _name(c: CameraResult) -> str:
    return c.camera.get("name") or c.camera["host"]


def _final(c: CameraResult) -> list[ControlResult]:
    return c.after or c.results


def _kv(pairs: list[tuple[str, object]]) -> str:
    return '<div class="kv">' + "".join(f"<b>{e(k)}</b><span>{e(v)}</span>" for k, v in pairs if v not in (None, "")) + "</div>"


def _baseline_label(meta: dict) -> str:
    from ..catalog import BUILTIN_PROFILES
    name = meta.get("baseline") or ""
    if not name:
        return "Every control (no baseline)" if meta.get("kind", "audit") in ("audit", "apply") else meta.get("profile", "")
    return f"{name}: {BUILTIN_PROFILES[name]}" if name in BUILTIN_PROFILES else f"{name} (custom profile)"


def _against_baseline(cams: list[CameraResult], meta: dict) -> list[CameraResult]:
    """Copies of the results scored against the run's baseline (controls outside it become N/A)."""
    import dataclasses
    ids, name = meta.get("baseline_ids"), meta.get("baseline") or ""
    if not ids:
        return cams
    return [dataclasses.replace(c, results=baseline_view(c.results, ids, name),
                                after=baseline_view(c.after, ids, name) if c.after else c.after) for c in cams]


def build_html(meta: dict, cams: list[CameraResult], catalog: Catalog, out: Path, classification: str = "",
               title: str = "AXIS camera hardening report", log_entries: list[dict] | None = None) -> Path:
    run_id = meta["run_id"]
    cls_bar = marking_bar(classification)
    cams = _against_baseline(cams, meta)
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
    customers = sorted({_customer(c) for c in cams if _customer(c)})
    tls = ("DISABLED (--insecure)" if meta.get("insecure_tls") else
           (f"CA bundle {meta['ca_bundle']}" if meta.get("ca_bundle") else "system trust store"))
    html = f"<h1>{e(title)}</h1>" + _kv([
        ("Type", KIND_TITLE.get(kind, kind) + (" - SIMULATED, no real camera touched" if meta.get("simulated") else "")),
        ("Run", meta["run_id"]), ("Operator", meta.get("operator") or "(not given)"),
        ("Date", (meta.get("started") or "")[:16].replace("T", " ")), ("Checked against", _baseline_label(meta)),
        ("Customer", meta.get("customer") or ", ".join(customers)), ("Site", meta.get("site_name")), ("TLS verification", tls),
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
    now = after if after is not None else before          # the actual (current) figure, never a before -> after
    if kind == "audit":
        stats.append(("Compliance", "n/a" if now is None else f"{now:.0f}%"))
        stats.append(("Problems", sum(r.status in (NON_COMPLIANT, ERROR) for c in reachable for r in c.results)))
    else:
        done = Counter(ch.get("status") for c in cams for ch in c.changes if "writes" in ch)
        stats.append(("Compliance", "n/a" if now is None else f"{now:.0f}%"))
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
    if meta.get("baseline_ids"):          # overview shows only what the baseline covers
        wanted = set(meta["baseline_ids"])
        ids = [cid for cid in ids if cid in wanted]
    reachable = [c for c in cams if c.reachable]
    if not reachable or not ids:
        return ""
    after = any(c.after for c in reachable)
    html = ("<h1>Overview</h1><p class=\"legend muted\">" +
            "".join(f'<span><b class="{c}">&nbsp;{s}&nbsp;</b> {e(t)}</span>' for st, (s, c, t) in SYMBOL.items() if st != NA) +
            ("<br>Showing the state <b>after</b> changes." if after else "") + "</p>")
    for start in range(0, len(reachable), MATRIX_COLS):
        chunk = reachable[start:start + MATRIX_COLS]
        html += '<table class="matrix"><tr><th>Control</th>' + "".join(
            f'<th class="cam" title="{e(c.camera["host"])}">{e(_name(c))}</th>' for c in chunk) + "</tr>"
        for level in LEVELS:
            level_ids = [i for i in ids if catalog.by_id[i].level == level]
            if not level_ids:
                continue
            html += f'<tr class="lvl"><td colspan="{1 + len(chunk)}">{e(LEVEL_TITLE[level])}</td></tr>'
            for cid in level_ids:
                html += f'<tr><td><span class="cid">{e(cid)}</span>{e(catalog.by_id[cid].title)}</td>'
                for cam in chunk:
                    r = next((x for x in _final(cam) if x.id == cid), None)
                    html += cell(r.status if r else NA, r.detail if r else "")
                html += "</tr>"
        html += "</table>"
    return html


def _found(observed: dict) -> str:
    """The camera's own settings in short form: shared prefixes dropped, long values cut, True/False as yes/no."""
    items = [(k.replace("root.", ""), v) for k, v in observed.items() if v is not None and not isinstance(v, (list, dict))]
    if not items:
        return ""
    keys = [k.split(".") for k, _ in items]
    if len(keys) > 1:
        common = 0
        while all(len(k) > common + 1 and k[common] == keys[0][common] for k in keys):
            common += 1
        names = [".".join(k[common:]) for k in keys]
    else:
        names = [".".join(keys[0][-2:])]

    def val(v) -> str:
        v = {True: "yes", False: "no"}.get(v, v) if isinstance(v, bool) else v
        v = str(v)
        return v if len(v) <= 40 else v[:37] + "..."
    return "; ".join(f"{n} = {val(v)}" for n, (_, v) in zip(names, items))


def _plain(r: ControlResult, ctl) -> tuple[str, str, str]:
    """(now, should be, note) in plain words. Raw camera values are shown separately (collapsed)."""
    if ctl is None:
        return r.detail, "", ""
    if ctl.kind == "apply":
        should = ctl.state_word("hardened")
        # notes that only restate a setting ("root.X='yes' (want no)", "allowAnonymous=True") add nothing here
        generic = "(want " in (r.detail or "") or "=" in (r.detail or "")
        if r.status == COMPLIANT:
            return should, should, "" if generic else r.detail
        if r.status == NON_COMPLIANT:
            return ctl.state_word("unhardened"), should, "" if generic else r.detail
        return r.detail or SYMBOL.get(r.status, ("", "", r.status))[2], should, ""
    return r.detail or SYMBOL.get(r.status, ("", "", r.status))[2], ctl.expect or "", ""


def _control_table(results: list[ControlResult], catalog: Catalog) -> str:
    html = ("<table class=\"ctl\"><tr><th></th><th>Control</th><th>p.</th><th>Now</th><th>Should be</th>"
            "<th>Note</th></tr>")
    for r in results:
        ctl = catalog.by_id.get(r.id)
        now, should, note = _plain(r, ctl)
        raw = _found(r.observed)
        raw_html = f'<div class="raw">{e(raw)}</div>' if raw else ""
        html += (f"<tr>{cell(r.status)}<td>{e(r.id)} {e(ctl.title if ctl else '')}</td>"
                 f"<td>{e(ctl.guide_page if ctl else '')}</td><td>{e(now)}{raw_html}</td>"
                 f"<td>{e(should)}</td><td>{e(note)}</td></tr>")
    return html + "</table>"


def _camera(cam: CameraResult, catalog: Catalog, meta: dict) -> str:
    c, d = cam.camera, cam.device
    cert = next((r.observed.get("issuer") for r in cam.results if r.id == "AX-C-004" and r.observed), "")
    final = _final(cam)
    p_now = compliance_pct(final) if final else None
    score = "" if p_now is None else f"{p_now:.0f}%"
    html = f'<section class="cam"><h1>{e(_name(cam))}</h1>' + _kv([
        ("IP", c["host"] + (f":{c['port']}" if c.get("port") else "")), ("Customer", c.get("customer") or c.get("site", "")),
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
                        f'<td rowspan="{n}">{e(ch["control_id"])} {e(ch["title"])}'
                        + (f'<br><span class="muted">{e(ch["now_label"])} &rarr; {e(ch["new_label"])}</span>'
                           if ch.get("now_label") and ch.get("new_label") else "") + "</td>") if first else ""
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
    groups = _info_groups(cams, catalog)
    if not failed and not any(groups.values()):
        return ""
    html = '<section class="cam"><h1>Follow-up</h1>'
    if failed:
        html += "<h2>Cameras needing attention</h2><table><tr><th>Camera</th><th>Status</th><th>Reason</th></tr>"
        html += "".join(f"<tr><td>{e(_name(c))}</td><td>{e(c.status)}</td><td>{e(c.error)}</td></tr>" for c in failed)
        html += "</table>"
    for key, heading, intro in INFO_GROUPS:
        items = groups[key]
        if not items or key == "manual":      # manual-check items are not listed in the report
            continue
        html += (f'<h2>{e(heading)}</h2><p class="muted">{e(intro)}</p>'
                 '<table class="fu"><tr><th>Check</th><th>p.</th><th>Camera(s)</th><th>What was found</th></tr>')
        for cid, findings in items:
            ctl = catalog.by_id[cid]
            for i, (detail, names) in enumerate(findings):
                lead = (f'<td rowspan="{len(findings)}">{e(cid)} {e(ctl.title)}</td>'
                        f'<td rowspan="{len(findings)}">{ctl.guide_page}</td>') if i == 0 else ""
                html += f"<tr>{lead}<td>{e(', '.join(names))}</td><td>{e(_plain_finding(ctl, detail))}</td></tr>"
        html += "</table>"
    return html + "</section>"


def _plain_finding(ctl, detail: str) -> str:
    """Follow-up table text without raw parameter syntax, e.g. "root.X='no' (want yes)" -> "Disabled (Enabled recommended)"."""
    import re
    m = re.search(r"='([^']*)' \(want ([^)]*)\)", detail or "")
    if m:
        words = {"yes": "Enabled", "no": "Disabled", "on": "Enabled", "off": "Disabled"}
        now, want = (words.get(x.lower(), x) for x in m.groups())
        return f"{now} ({ctl.expect or want} recommended)"
    return detail


INFO_GROUPS = [
    ("manual", "Needs a manual check",
     "The tool could not read these settings from the camera. Check them in the camera's web page."),
    ("decision", "Your decision (depends on the site)",
     "Read from the camera. Whether this is right depends on your network or VMS, so the tool does not mark it "
     "pass or fail."),
    ("info", "For information",
     "Read from the camera automatically. There is no pass or fail for these; they are listed for your records."),
]


def _info_group(ctl, detail: str) -> str:
    if ctl.handler == "manual" or "manual" in (detail or "").lower():
        return "manual"
    return "decision" if ctl.followup == "decision" else "info"


def _info_groups(cams: list[CameraResult], catalog: Catalog) -> dict[str, list]:
    """{group: [(control id, [(finding, [camera names])])]} for every INFO result, grouped by what to do with it."""
    found: dict[str, dict[str, dict[str, list[str]]]] = {k: {} for k, _, _ in INFO_GROUPS}
    for c in cams:
        for r in _final(c):
            ctl = catalog.by_id.get(r.id)
            if r.status != INFO or ctl is None:
                continue
            g = _info_group(ctl, r.detail)
            found[g].setdefault(r.id, {}).setdefault(r.detail or "(no detail)", []).append(_name(c))
    order = {ctl.id: i for i, ctl in enumerate(catalog.controls)}
    return {g: [(cid, list(by_detail.items())) for cid, by_detail in sorted(items.items(), key=lambda x: order[x[0]])]
            for g, items in found.items()}


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
