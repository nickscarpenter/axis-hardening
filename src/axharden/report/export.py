"""CSV and JSON export of a run (same data as the PDF, no credentials)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from ..audit import CameraResult, write_private
from ..catalog import Catalog


def export_json(meta: dict, cams: list[CameraResult], out: Path) -> Path:
    doc = {"run": meta, "cameras": [c.to_dict() for c in cams]}
    write_private(out, json.dumps(doc, indent=1, default=str))
    return out


def export_csv(meta: dict, cams: list[CameraResult], catalog: Catalog, out: Path) -> Path:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["run_id", "site", "camera", "host", "model", "serial", "axis_os", "camera_status",
                "control_id", "title", "level", "guide_page", "csc", "status", "observed", "detail"])
    for cam in cams:
        base = [meta["run_id"], cam.camera.get("site", ""), cam.camera.get("name", ""), cam.camera["host"],
                cam.device.get("ProdNbr", ""), cam.device.get("SerialNumber", ""), cam.device.get("Version", ""),
                cam.status]
        if not cam.results:
            w.writerow(base + ["", "", "", "", "", "", "", cam.error])
            continue
        for r in cam.results:
            ctl = catalog.by_id.get(r.id)
            observed = "; ".join(f"{k}={v}" for k, v in r.observed.items()) if r.observed else ""
            w.writerow(base + [r.id, ctl.title if ctl else "", ctl.level if ctl else "",
                               ctl.guide_page if ctl else "", " ".join(ctl.csc) if ctl else "",
                               r.status, observed[:500], r.detail])
    write_private(out, buf.getvalue())
    return out
