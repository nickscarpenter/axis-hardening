"""Report outputs for a saved run."""

from __future__ import annotations

from pathlib import Path


def write_reports(run_dir: Path, catalog, classification: str = "", out: str | Path | None = None) -> list[Path]:
    """Write the HTML report plus CSV and JSON exports for a run. Returns [html, csv, json]."""
    from ..audit import load_run
    from ..auditlog import entries_for_run
    from .export import export_csv, export_json
    from .html import build_html

    meta, cams = load_run(run_dir)
    log_entries = entries_for_run(run_dir.parent.parent / "audit_log.jsonl", meta["run_id"])
    html_path = Path(out) if out else run_dir / f"report-{meta['run_id']}.html"
    build_html(meta, cams, catalog, html_path, classification=classification, log_entries=log_entries)
    csv_path = export_csv(meta, cams, catalog, html_path.with_suffix(".csv"))
    json_path = export_json(meta, cams, html_path.with_suffix(".json"))
    return [html_path, csv_path, json_path]
