"""Tkinter GUI for non-technical operators (standard library only).

One window, three steps: choose the camera list, fill in a few details, press Run. After a check,
"Fix problems..." previews every change with a tick box; nothing is written until the user confirms.
"Undo last changes" restores the previous values. Credentials stay in memory exactly as in the CLI.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
import tkinter as tk
from tkinter import ttk

from .. import GUIDE_REF, __version__
from ..apply import build_rollback, make_plan, run_apply, run_rollback
from ..audit import AuditSettings, CameraResult, load_fixture_cameras, run_audit, simulated_factory
from ..catalog import load_catalog, load_profile, resource_dir
from ..evaluate import NON_COMPLIANT, compliance_pct
from ..inventory import Camera, InventoryError, load_inventory, password_findings, write_templates
from ..logging_setup import setup_logging
from ..report import write_reports
from ..vapix.client import TLSPolicy

APP_TITLE = "AXIS Camera Hardening Check"

# Plain-English explanations of camera-level problems.
FRIENDLY = {
    "OK": "Checked successfully.",
    "OUT_OF_SCOPE": "Checked, but this camera runs AXIS OS older than 10.0, which this tool is not designed for. "
                    "Ask for the camera to be upgraded.",
    "UNREACHABLE": "Could not reach the camera. Check the IP address in the camera list, and that this PC is "
                   "connected to the camera network.",
    "AUTH_FAILED": "The camera rejected the username or password. Check them in the camera list. "
                   "(The tool does not try again, so the camera will not lock you out.)",
    "TLS_ERROR": "This PC does not trust the camera's security certificate. If you are on the camera network and "
                 "sure the IP address is right, choose \"Accept the cameras' own certificates\" in step 2 and run again.",
    "INSECURE_AUTH_REFUSED": "The camera only allows an unencrypted login, so the password was not sent. "
                             "Set the protocol column to https for this camera.",
    "HTTP_ERROR": "The camera gave an unexpected answer. Try again; if it keeps happening, report it.",
    "ERROR": "Something went wrong while checking this camera. See the details in the report.",
    "LOST_CONTACT": "The camera stopped answering after a change (usually HTTPS-only). Work on it stopped. "
                    "Check the camera can still be reached over HTTPS; use \"Undo last changes\" if needed.",
}
STATUS_LABEL = {"OK": "Checked", "OUT_OF_SCOPE": "Checked (old firmware)", "UNREACHABLE": "Not reachable",
                "AUTH_FAILED": "Wrong password", "TLS_ERROR": "Certificate problem",
                "INSECURE_AUTH_REFUSED": "Insecure login refused", "HTTP_ERROR": "Camera error", "ERROR": "Error",
                "LOST_CONTACT": "Lost contact!"}
TLS_MODES = {
    "verify": "Normal: only trust certificates this PC already trusts",
    "ca": "Use our organisation's CA certificate file",
    "insecure": "Accept the cameras' own certificates (closed camera network only)",
}
MARKINGS = ["", "OFFICIAL", "OFFICIAL-SENSITIVE"]


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path.cwd()


def open_path(path: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # noqa: S606 - local file/folder only
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


class Cancelled(Exception):
    pass


class App:
    def __init__(self, root: tk.Tk, output_dir: str | None = None):
        self.root = root
        self.catalog = load_catalog()
        self.cameras: list[Camera] = []
        self.inventory_path: Path | None = None
        self.queue: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.last_report: Path | None = None
        self.last_run_dir: Path | None = None
        self.results: dict[str, CameraResult] = {}
        # state for fixing problems
        self.factory = None              # None = real cameras; set for the demo
        self.sim_devices = None
        self.settings: AuditSettings | None = None
        self.pf = None
        self.audit_run_id: str | None = None
        self.audit_results: list[CameraResult] = []
        self.audit_cams: list[Camera] = []
        self.audit_time = 0.0
        self.last_apply_dir: Path | None = None

        self.var_inventory = tk.StringVar(value="No camera list chosen yet")
        self.var_summary = tk.StringVar()
        self.var_operator = tk.StringVar()
        self.var_marking = tk.StringVar()
        self.var_site = tk.StringVar(value="All sites")
        self.var_tls = tk.StringVar(value="verify")
        self.var_ca = tk.StringVar()
        self.var_output = tk.StringVar(value=str(Path(output_dir) if output_dir else app_dir() / "output"))
        self.var_progress_text = tk.StringVar(value="")

        self._load_settings()
        self._build()
        self.root.after(100, self._poll)

    # ------------------------------------------------------------------ settings (no secrets)
    @property
    def settings_path(self) -> Path:
        return Path(self.var_output.get()) / "gui_settings.json"

    def _load_settings(self) -> None:
        try:
            s = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.var_operator.set(s.get("operator", ""))
        self.var_marking.set(s.get("marking", ""))
        if s.get("tls") in TLS_MODES:
            self.var_tls.set(s["tls"])
        self.var_ca.set(s.get("ca_bundle", ""))

    def _save_settings(self) -> None:
        data = {"operator": self.var_operator.get(), "marking": self.var_marking.get(),
                "tls": self.var_tls.get(), "ca_bundle": self.var_ca.get()}
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(json.dumps(data, indent=1), encoding="utf-8")
        except OSError:
            pass

    # ------------------------------------------------------------------ layout
    def _build(self) -> None:
        r = self.root
        r.title(APP_TITLE)
        r.minsize(900, 640)
        style = ttk.Style(r)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Step.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        style.configure("Big.TButton", font=("Segoe UI", 11, "bold"), padding=(18, 8))
        style.configure("Warn.TLabel", foreground="#9a5b00")
        style.configure("Muted.TLabel", foreground="#555555")

        self._menu()
        outer = ttk.Frame(r, padding=14)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)

        ttk.Label(outer, text=APP_TITLE, style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(outer, text="Checks each camera's security settings and writes a report. "
                  "Nothing on a camera changes unless you press \"Fix problems...\" and confirm.", style="Muted.TLabel").grid(row=1, column=0, sticky="w",
                                                                                        pady=(0, 10))

        # Step 1
        s1 = ttk.LabelFrame(outer, text="  1. Camera list  ", style="Step.TLabelframe", padding=10)
        s1.grid(row=2, column=0, sticky="ew")
        s1.columnconfigure(0, weight=1)
        ttk.Entry(s1, textvariable=self.var_inventory, state="readonly").grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(s1, text="Choose camera list...", command=self.choose_inventory).grid(row=0, column=1)
        ttk.Button(s1, text="Make a blank list...", command=self.make_template).grid(row=0, column=2, padx=(6, 0))
        ttk.Label(s1, textvariable=self.var_summary).grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.lbl_warn = ttk.Label(s1, text="", style="Warn.TLabel", wraplength=820, justify="left")
        self.lbl_warn.grid(row=2, column=0, columnspan=3, sticky="w")

        # Step 2
        s2 = ttk.LabelFrame(outer, text="  2. Details  ", style="Step.TLabelframe", padding=10)
        s2.grid(row=3, column=0, sticky="ew", pady=10)
        s2.columnconfigure(1, weight=1)
        ttk.Label(s2, text="Your name").grid(row=0, column=0, sticky="w")
        ttk.Entry(s2, textvariable=self.var_operator, width=34).grid(row=0, column=1, sticky="w", pady=2)
        ttk.Label(s2, text="Report marking").grid(row=1, column=0, sticky="w")
        ttk.Combobox(s2, textvariable=self.var_marking, values=MARKINGS, width=31).grid(row=1, column=1, sticky="w", pady=2)
        ttk.Label(s2, text="Which cameras").grid(row=2, column=0, sticky="w")
        self.cmb_site = ttk.Combobox(s2, textvariable=self.var_site, values=["All sites"], state="readonly", width=31)
        self.cmb_site.grid(row=2, column=1, sticky="w", pady=2)
        ttk.Label(s2, text="Certificates").grid(row=3, column=0, sticky="nw", pady=(4, 0))
        tls = ttk.Frame(s2)
        tls.grid(row=3, column=1, sticky="w", pady=(4, 0))
        for i, (key, text) in enumerate(TLS_MODES.items()):
            ttk.Radiobutton(tls, text=text, value=key, variable=self.var_tls,
                            command=self._tls_changed).grid(row=i, column=0, sticky="w")
        caf = ttk.Frame(tls)
        caf.grid(row=1, column=1, sticky="w", padx=(8, 0))
        self.ent_ca = ttk.Entry(caf, textvariable=self.var_ca, width=30)
        self.ent_ca.pack(side="left")
        self.btn_ca = ttk.Button(caf, text="Browse...", command=self.choose_ca)
        self.btn_ca.pack(side="left", padx=(4, 0))
        ttk.Label(s2, text="Save reports in").grid(row=4, column=0, sticky="w", pady=(6, 0))
        outf = ttk.Frame(s2)
        outf.grid(row=4, column=1, sticky="ew", pady=(6, 0))
        outf.columnconfigure(0, weight=1)
        ttk.Entry(outf, textvariable=self.var_output).grid(row=0, column=0, sticky="ew")
        ttk.Button(outf, text="Change...", command=self.choose_output).grid(row=0, column=1, padx=(4, 0))
        self._tls_changed()

        # Step 3
        s3 = ttk.LabelFrame(outer, text="  3. Run the check  ", style="Step.TLabelframe", padding=10)
        s3.grid(row=4, column=0, sticky="nsew")
        outer.rowconfigure(4, weight=1)
        s3.columnconfigure(1, weight=1)
        s3.rowconfigure(1, weight=1)
        self.btn_run = ttk.Button(s3, text="Run check", style="Big.TButton", command=self.run, state="disabled")
        self.btn_run.grid(row=0, column=0, sticky="w")
        pf = ttk.Frame(s3)
        pf.grid(row=0, column=1, sticky="ew", padx=12)
        pf.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(pf, mode="determinate")
        self.progress.grid(row=0, column=0, sticky="ew")
        ttk.Label(pf, textvariable=self.var_progress_text, style="Muted.TLabel").grid(row=1, column=0, sticky="w")

        cols = ("camera", "ip", "model", "os", "result", "score", "issues")
        heads = ("Camera", "IP address", "Model", "AXIS OS", "Result", "Score", "Problems found")
        widths = (170, 130, 110, 90, 150, 60, 110)
        tf = ttk.Frame(s3)
        tf.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        tf.columnconfigure(0, weight=1)
        tf.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", height=8)
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.tag_configure("bad", foreground="#b3261e")
        self.tree.tag_configure("ok", foreground="#1e7b34")
        self.tree.bind("<Double-1>", self._show_row)
        ttk.Label(s3, text="Double-click a camera to see what a problem means.", style="Muted.TLabel").grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        bf = ttk.Frame(s3)
        bf.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        self.btn_fix = ttk.Button(bf, text="Fix problems...", style="Big.TButton", command=self.open_fix,
                                  state="disabled")
        self.btn_fix.pack(side="left")
        self.btn_undo = ttk.Button(bf, text="Undo last changes", command=self.undo, state="disabled")
        self.btn_undo.pack(side="left", padx=(6, 0))
        self.btn_report = ttk.Button(bf, text="Open report", command=self.open_report, state="disabled")
        self.btn_folder = ttk.Button(bf, text="Open report folder", command=self.open_folder, state="disabled")
        self.btn_folder.pack(side="right")
        self.btn_report.pack(side="right", padx=(0, 6))

    def _menu(self) -> None:
        m = tk.Menu(self.root)
        f = tk.Menu(m, tearoff=False)
        f.add_command(label="Choose camera list...", command=self.choose_inventory)
        f.add_command(label="Make a blank camera list...", command=self.make_template)
        f.add_separator()
        f.add_command(label="Exit", command=self.root.destroy)
        m.add_cascade(label="File", menu=f)
        t = tk.Menu(m, tearoff=False)
        t.add_command(label="Try a demo (no cameras needed)", command=self.run_demo)
        t.add_command(label="Open reports folder", command=lambda: self._open_dir(Path(self.var_output.get())))
        t.add_separator()
        t.add_command(label="Advanced: check catalog against one camera...", command=self.run_discover)
        m.add_cascade(label="Tools", menu=t)
        h = tk.Menu(m, tearoff=False)
        h.add_command(label="How to use", command=self.show_help)
        h.add_command(label="About", command=self.show_about)
        m.add_cascade(label="Help", menu=h)
        self.root.config(menu=m)

    # ------------------------------------------------------------------ step 1
    def _ask_password(self, username: str) -> str:
        pw = simpledialog.askstring("Camera password",
                                    f"The camera list has no password for user '{username}'.\n"
                                    f"Type the password for '{username}' (used for every camera with this user):",
                                    show="*", parent=self.root)
        if pw is None:
            raise Cancelled()
        return pw

    def choose_inventory(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="Choose the camera list",
                                          filetypes=[("Camera lists", "*.xlsx *.csv"), ("All files", "*.*")])
        if path:
            self.load_inventory(Path(path))

    def load_inventory(self, path: Path) -> bool:
        try:
            cams = load_inventory(path, prompt=self._ask_password)
        except Cancelled:
            return False
        except InventoryError as e:
            lines = e.errors[:15] + ([f"...and {len(e.errors) - 15} more"] if len(e.errors) > 15 else [])
            messagebox.showerror("Problems in the camera list",
                                 "Please fix these in the camera list and choose it again:\n\n" + "\n".join(lines),
                                 parent=self.root)
            return False
        except Exception as e:  # e.g. file open in Excel
            messagebox.showerror("Could not read the camera list", f"{type(e).__name__}: {e}\n\n"
                                 "If the file is open in Excel, close it and try again.", parent=self.root)
            return False
        self.cameras, self.inventory_path = cams, path
        self.var_inventory.set(str(path))
        sites = sorted({c.site for c in cams if c.site})
        self.cmb_site.configure(values=["All sites"] + sites)
        self.var_site.set("All sites")
        self.var_summary.set(f"{len(cams)} camera(s) loaded" + (f" across {len(sites)} site(s)" if sites else ""))
        pf = password_findings(cams)
        warn = []
        for g in pf.shared_groups:
            warn.append(f"Warning: {len(g)} cameras share the same password ({', '.join(g[:4])}"
                        f"{'...' if len(g) > 4 else ''}). The guide recommends a unique password per camera.")
        if pf.weak:
            warn.append(f"Warning: passwords shorter than 8 characters on {', '.join(pf.weak[:4])}"
                        f"{'...' if len(pf.weak) > 4 else ''}.")
        self.lbl_warn.configure(text="\n".join(warn))
        self.tree.delete(*self.tree.get_children())
        for c in cams:
            self.tree.insert("", "end", iid=c.host, values=(c.name or c.host, c.address, "", "", "Waiting", "", ""))
        self.btn_run.configure(state="normal")
        return True

    def make_template(self) -> None:
        folder = filedialog.askdirectory(parent=self.root, title="Where should the blank camera list go?")
        if not folder:
            return
        paths = write_templates(folder)
        messagebox.showinfo("Blank camera list created",
                            "Created:\n" + "\n".join(str(p) for p in paths) +
                            "\n\nFill in one row per camera: ip and username are required. Leave the password "
                            "column empty and the tool will ask for it, so the file holds no passwords.",
                            parent=self.root)
        self._open_dir(Path(folder))

    # ------------------------------------------------------------------ step 2
    def _tls_changed(self) -> None:
        state = "normal" if self.var_tls.get() == "ca" else "disabled"
        self.ent_ca.configure(state=state)
        self.btn_ca.configure(state=state)

    def choose_ca(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="Choose the CA certificate file",
                                          filetypes=[("Certificates", "*.pem *.crt *.cer"), ("All files", "*.*")])
        if path:
            self.var_ca.set(path)

    def choose_output(self) -> None:
        folder = filedialog.askdirectory(parent=self.root, title="Where should reports be saved?")
        if folder:
            self.var_output.set(folder)

    def _tls_policy(self) -> TLSPolicy | None:
        mode = self.var_tls.get()
        if mode == "insecure":
            return TLSPolicy(verify=False)
        if mode == "ca":
            ca = self.var_ca.get().strip()
            if not ca or not Path(ca).exists():
                messagebox.showerror("CA file missing", "Choose the CA certificate file, or pick another "
                                     "certificate option.", parent=self.root)
                return None
            return TLSPolicy(verify=ca)
        return TLSPolicy(verify=True)

    # ------------------------------------------------------------------ step 3
    def _busy(self, busy: bool) -> None:
        self.btn_run.configure(state="disabled" if busy or not self.cameras else "normal")
        if busy:
            for b in (self.btn_report, self.btn_folder, self.btn_fix, self.btn_undo):
                b.configure(state="disabled")

    def run(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        if not self.var_operator.get().strip():
            messagebox.showwarning("Your name", "Please type your name in step 2. It goes on the report.",
                                   parent=self.root)
            return
        tls = self._tls_policy()
        if tls is None:
            return
        site = self.var_site.get()
        cams = [c for c in self.cameras if site == "All sites" or c.site == site]
        self._save_settings()
        self.sim_devices = None
        self._start(cams, tls, factory=None)

    def run_demo(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        demo = resource_dir() / "catalog" / "demo"
        loaded = load_fixture_cameras(demo) if demo.exists() else []
        if not loaded:
            messagebox.showerror("Demo", "Demo data is missing from this copy of the tool.", parent=self.root)
            return
        self.cameras = [c for c, _ in loaded]
        self.var_inventory.set("DEMO - recorded camera data, no network")
        self.var_summary.set(f"{len(self.cameras)} demo camera(s)")
        self.lbl_warn.configure(text="")
        self.tree.delete(*self.tree.get_children())
        for c in self.cameras:
            self.tree.insert("", "end", iid=c.host, values=(c.name or c.host, c.address, "", "", "Waiting", "", ""))
        factory, self.sim_devices = simulated_factory(loaded)
        self._start(self.cameras, TLSPolicy(), factory=factory)

    def _start(self, cams: list[Camera], tls: TLSPolicy, factory=None) -> None:
        if not cams:
            messagebox.showinfo("No cameras", "No cameras match the chosen site.", parent=self.root)
            return
        for c in cams:
            if self.tree.exists(c.host):
                self.tree.item(c.host, values=(c.name or c.host, c.address, "", "", "Checking...", "", ""), tags=())
        self.results.clear()
        self.progress.configure(maximum=len(cams), value=0)
        self.var_progress_text.set(f"Checking {len(cams)} camera(s)...")
        self._busy(True)
        settings = AuditSettings(tls=tls, operator=self.var_operator.get().strip() or "(demo)")
        marking = self.var_marking.get().strip()
        out = Path(self.var_output.get())
        pf = password_findings(cams) if factory is None else password_findings([])
        self.factory, self.settings, self.pf, self.audit_cams = factory, settings, pf, cams
        self.last_apply_dir = None

        def work() -> None:
            profile = load_profile("audit-only", self.catalog)
            run_id, run_dir, results = run_audit(cams, self.catalog, profile, settings, pf, out,
                                                 client_factory=factory,
                                                 progress=lambda r: self.queue.put(("camera", r)),
                                                 simulated=factory is not None)
            html, _, _ = write_reports(run_dir, self.catalog, marking)
            self.queue.put(("done", run_dir, html, "audit", (run_id, results)))

        self._run_worker(work)

    def _run_worker(self, work) -> None:
        def wrapped() -> None:
            try:
                work()
            except Exception as e:
                self.queue.put(("failed", f"{type(e).__name__}: {e}", traceback.format_exc()))
        self.worker = threading.Thread(target=wrapped, daemon=True)
        self.worker.start()

    def _poll(self) -> None:
        try:
            while True:
                msg = self.queue.get_nowait()
                if msg[0] == "camera":
                    self._camera_done(msg[1])
                elif msg[0] == "changed":
                    self._camera_changed(msg[1])
                elif msg[0] == "done":
                    self._finished(*msg[1:])
                elif msg[0] == "failed":
                    self._busy(False)
                    self.var_progress_text.set("The check stopped because of an error.")
                    messagebox.showerror("Check failed", msg[1], parent=self.root)
                elif msg[0] == "discover":
                    self._discover_done(*msg[1:])
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _camera_done(self, r: CameraResult) -> None:
        self.results[r.camera["host"]] = r
        self.progress.step(1)
        done, total = int(self.progress["value"]), int(self.progress["maximum"])
        self.var_progress_text.set(f"Checked {done} of {total}")
        pct = compliance_pct(r.results) if r.reachable else None
        issues = sum(x.status == NON_COMPLIANT for x in r.results)
        values = (r.camera.get("name") or r.camera["host"], r.camera["host"], r.device.get("ProdNbr", ""),
                  r.device.get("Version", ""), STATUS_LABEL.get(r.status, r.status),
                  "" if pct is None else f"{pct:.0f}%", str(issues) if r.reachable else "")
        tag = "ok" if r.status == "OK" and issues == 0 else ("bad" if not r.reachable or issues else "")
        if self.tree.exists(r.camera["host"]):
            self.tree.item(r.camera["host"], values=values, tags=(tag,))
        else:
            self.tree.insert("", "end", iid=r.camera["host"], values=values, tags=(tag,))

    def _camera_changed(self, r: CameraResult) -> None:
        """A camera finished an apply/undo run."""
        self.results[r.camera["host"]] = r
        self.progress.step(1)
        done, total = int(self.progress["value"]), int(self.progress["maximum"])
        self.var_progress_text.set(f"Changed {done} of {total} camera(s)")
        changes = [c for c in r.changes if "writes" in c]
        ok = sum(c["status"] == "verified" for c in changes)
        bad = sum(c["status"] in ("failed", "skipped") for c in changes)
        if r.status == "LOST_CONTACT":
            result = "Lost contact!"
        elif r.status != "OK":
            result = STATUS_LABEL.get(r.status, r.status)
        else:
            result = f"{ok} changed" + (f", {bad} failed" if bad else "")
        final = r.after or r.results
        pct = compliance_pct(final) if final else None
        issues = sum(x.status == NON_COMPLIANT for x in final)
        tag = "bad" if bad or r.status != "OK" else ("ok" if issues == 0 else "")
        values = (r.camera.get("name") or r.camera["host"], r.camera["host"], r.device.get("ProdNbr", ""),
                  r.device.get("Version", ""), result, "" if pct is None else f"{pct:.0f}%", str(issues))
        if self.tree.exists(r.camera["host"]):
            self.tree.item(r.camera["host"], values=values, tags=(tag,))

    def _finished(self, run_dir: Path, html: Path, kind: str = "audit", extra=None) -> None:
        self._busy(False)
        self.last_run_dir, self.last_report = run_dir, html
        self.btn_report.configure(state="normal")
        self.btn_folder.configure(state="normal")
        results = list(self.results.values())
        if kind == "audit":
            self.audit_run_id, self.audit_results = extra
            self.audit_time = time.monotonic()
            failed = [r for r in results if not r.reachable]
            text = f"Check finished. Report saved: {html.name}"
            if failed:
                text += f"  ({len(failed)} camera(s) could not be checked: double-click them for help)"
            fixable = self._plans("basic-full")
            n = sum(len(p.changes) for p in fixable)
            if n:
                self.btn_fix.configure(state="normal")
                text += f"\n{n} problem(s) can be fixed automatically: click \"Fix problems...\"."
            title = "Check finished"
        else:
            changes = [c for r in results for c in r.changes if "writes" in c]
            ok = sum(c["status"] == "verified" for c in changes)
            bad = sum(c["status"] in ("failed", "skipped") for c in changes)
            lost = [r for r in results if r.status == "LOST_CONTACT"]
            verb = "Changed" if kind == "apply" else "Restored"
            text = f"{verb} and verified {ok} setting(s)." + (f" {bad} could not be changed." if bad else "")
            if lost:
                text += (f"\nWARNING: lost contact with {len(lost)} camera(s) after a change. Check them "
                         "(and that HTTPS works) before doing anything else.")
            if kind == "apply":
                self.last_apply_dir = run_dir
                self.btn_undo.configure(state="normal")
                if any(c.get("requires_reboot") and c["status"] == "verified" for c in changes):
                    text += "\nThe TLS cipher change takes effect after the camera is restarted."
            text += "\nRun the check again to confirm the result."
            title = "Changes finished" if kind == "apply" else "Undo finished"
        self.var_progress_text.set(text.replace("\n", "  "))
        if messagebox.askyesno(title, f"{text}\n\nOpen the report now?", parent=self.root):
            self.open_report()

    # ------------------------------------------------------------------ fixing problems (phase 2)
    def _plans(self, profile_name: str):
        if not self.audit_results:
            return []
        profile = load_profile(profile_name, self.catalog)
        by_host = {c.host for c in self.audit_cams}
        audits = [r for r in self.audit_results if r.camera["host"] in by_host]
        return make_plan(audits, self.audit_cams, self.catalog, profile, lambda n: load_profile(n, self.catalog))

    def open_fix(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        if self.factory is None and time.monotonic() - self.audit_time > 30 * 60:
            if not messagebox.askyesno("Check is out of date", "The last check was more than 30 minutes ago. "
                                       "Camera settings may have changed since.\n\nContinue anyway? "
                                       "(Choose No and press \"Run check\" first.)", parent=self.root):
                return
        FixDialog(self)

    def start_apply(self, plans, profile) -> None:
        cams = [p.camera for p in plans if p.changes]
        self.progress.configure(maximum=len(cams), value=0)
        self.var_progress_text.set(f"Changing settings on {len(cams)} camera(s)...")
        for p in plans:
            if p.changes and self.tree.exists(p.camera.host):
                vals = list(self.tree.item(p.camera.host, "values"))
                vals[4] = "Changing..."
                self.tree.item(p.camera.host, values=vals, tags=())
        self._busy(True)
        self.results.clear()
        marking = self.var_marking.get().strip()
        out = Path(self.var_output.get())
        todo = [p for p in plans if p.changes]

        def work() -> None:
            _, run_dir, _ = run_apply(todo, self.catalog, profile, self.settings, self.pf, out, "gui",
                                      self.audit_run_id or "", client_factory=self.factory,
                                      progress=lambda r: self.queue.put(("changed", r)),
                                      simulated=self.factory is not None)
            html, _, _ = write_reports(run_dir, self.catalog, marking)
            self.queue.put(("done", run_dir, html, "apply", None))

        self._run_worker(work)

    def undo(self) -> None:
        if not self.last_apply_dir or (self.worker and self.worker.is_alive()):
            return
        try:
            _, plans = build_rollback(self.last_apply_dir, self.audit_cams)
        except ValueError as e:
            messagebox.showerror("Cannot undo", str(e), parent=self.root)
            return
        n = sum(len(ch.writes) for p in plans for ch in p.changes)
        if not n:
            messagebox.showinfo("Nothing to undo", "No settings were changed in the last run.", parent=self.root)
            return
        if not messagebox.askyesno("Undo last changes",
                                   f"Put {n} setting(s) on {len(plans)} camera(s) back to how they were "
                                   "before the last changes?", parent=self.root):
            return
        self.progress.configure(maximum=len(plans), value=0)
        self._busy(True)
        self.results.clear()
        marking = self.var_marking.get().strip()
        out = Path(self.var_output.get())
        apply_dir = self.last_apply_dir

        def work() -> None:
            _, run_dir, _ = run_rollback(apply_dir, plans, self.catalog, self.settings, out, "gui",
                                         client_factory=self.factory,
                                         progress=lambda r: self.queue.put(("changed", r)),
                                         simulated=self.factory is not None)
            html, _, _ = write_reports(run_dir, self.catalog, marking)
            self.queue.put(("done", run_dir, html, "rollback", None))

        self.last_apply_dir = None
        self._run_worker(work)

    def _show_row(self, _event: object) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        r = self.results.get(sel[0])
        if r is None:
            messagebox.showinfo("Not checked yet", "Press \"Run check\" first.", parent=self.root)
            return
        lines = [FRIENDLY.get(r.status, r.status)]
        if r.error:
            lines.append(f"\nTechnical detail: {r.error}")
        bad = [x for x in r.results if x.status == NON_COMPLIANT]
        if bad:
            lines.append(f"\n{len(bad)} setting(s) do not meet the hardening guide:")
            for x in bad[:12]:
                ctl = self.catalog.by_id.get(x.id)
                lines.append(f"  • {ctl.title if ctl else x.id}")
            if len(bad) > 12:
                lines.append(f"  ...and {len(bad) - 12} more (see the report)")
        messagebox.showinfo(r.camera.get("name") or r.camera["host"], "\n".join(lines), parent=self.root)

    def open_report(self) -> None:
        if self.last_report and self.last_report.exists():
            webbrowser.open(self.last_report.resolve().as_uri())

    def open_folder(self) -> None:
        if self.last_run_dir:
            self._open_dir(self.last_run_dir)

    def _open_dir(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        open_path(path)

    # ------------------------------------------------------------------ advanced
    def run_discover(self) -> None:
        if not self.cameras or self.inventory_path is None:
            messagebox.showinfo("Choose a camera list first", "Load a camera list in step 1 first.", parent=self.root)
            return
        sel = self.tree.selection()
        default = sel[0] if sel else self.cameras[0].host
        host = simpledialog.askstring("Check catalog against a camera",
                                      "IP address of the reference camera (must be in the camera list):",
                                      initialvalue=default, parent=self.root)
        if not host:
            return
        cam = next((c for c in self.cameras if c.host == host or c.address == host), None)
        if cam is None:
            messagebox.showerror("Not in list", f"{host} is not in the camera list.", parent=self.root)
            return
        tls = self._tls_policy()
        if tls is None:
            return
        self.var_progress_text.set(f"Reading all settings from {host}...")
        self._busy(True)

        def work() -> None:
            from ..discover import run_discover
            try:
                res = run_discover(cam, self.catalog, tls, Path(self.var_output.get()))
                self.queue.put(("discover", res, None))
            except Exception as e:
                self.queue.put(("discover", None, f"{getattr(e, 'code', type(e).__name__)}: {e}"))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def _discover_done(self, res, error) -> None:
        self._busy(False)
        if error:
            self.var_progress_text.set("Catalog check failed.")
            messagebox.showerror("Catalog check failed", error, parent=self.root)
            return
        missing = [c for c in res.checks if c.status in ("missing", "pattern_none")]
        case = [c for c in res.checks if c.status == "case_differs"]
        msg = (f"{res.device.get('ProdFullName', '?')}, AXIS OS {res.device.get('Version', '?')}\n"
               f"{res.params_count} settings read.\n\n")
        msg += ("Settings missing on this firmware:\n" + "\n".join(f"  {c.control_id}  {c.name}" for c in missing)
                if missing else "Every catalog setting was found.") + "\n"
        if case:
            msg += "\nSpelling differs:\n" + "\n".join(f"  {c.name} -> {c.actual}" for c in case) + "\n"
        msg += f"\nSaved to:\n{res.out_dir}\n\nSend this folder to the tool maintainer."
        self.var_progress_text.set("Catalog check finished.")
        messagebox.showinfo("Catalog check", msg, parent=self.root)
        self._open_dir(res.out_dir)

    def show_help(self) -> None:
        messagebox.showinfo("How to use", (
            "1. Camera list: choose the Excel or CSV file listing your cameras (ip, username, password).\n"
            "   No list yet? Use \"Make a blank list\". Leave passwords empty and the tool will ask for them.\n\n"
            "2. Details: type your name. Pick a report marking if your organisation needs one.\n"
            "   If cameras show \"Certificate problem\", choose \"Accept the cameras' own certificates\".\n\n"
            "3. Press Run check. When it finishes, open the report.\n\n"
            "The tool only reads settings. It never changes the cameras, and never saves passwords.\n"
            "Want to see what it does first? Tools > Try a demo."), parent=self.root)

    def show_about(self) -> None:
        messagebox.showinfo("About", f"{APP_TITLE}\naxharden {__version__}\n\nChecks against the {GUIDE_REF}.\n"
                            f"Catalog SHA-256: {self.catalog.sha256[:16]}...", parent=self.root)


FIX_PROFILES = {
    "basic-safe": "Recommended changes (safe for normal use)",
    "basic-full": "Recommended + turn off the web interface and hide the server version (Axis's full hardening)",
}
TICK, UNTICK = "☑", "☐"


class FixDialog:
    """Preview of every change, with a tick box per change. Nothing is written until the user confirms."""

    def __init__(self, app: "App"):
        self.app = app
        self.win = tk.Toplevel(app.root)
        self.win.title("Fix problems")
        self.win.transient(app.root)
        self.win.minsize(860, 480)
        self.var_profile = tk.StringVar(value="basic-safe")
        self.plans = []
        self.ticked: set[str] = set()
        self.changes: dict[str, tuple] = {}   # iid -> (plan, change)

        f = ttk.Frame(self.win, padding=12)
        f.pack(fill="both", expand=True)
        f.columnconfigure(0, weight=1)
        f.rowconfigure(2, weight=1)
        ttk.Label(f, text="These settings will be changed to match the Axis hardening guide. Untick anything you "
                  "do not want changed. Nothing happens until you press Apply.", wraplength=820).grid(
            row=0, column=0, sticky="w")
        pf = ttk.Frame(f)
        pf.grid(row=1, column=0, sticky="w", pady=8)
        for key, text in FIX_PROFILES.items():
            ttk.Radiobutton(pf, text=text, value=key, variable=self.var_profile, command=self.refresh).pack(anchor="w")

        tf = ttk.Frame(f)
        tf.grid(row=2, column=0, sticky="nsew")
        tf.columnconfigure(0, weight=1)
        tf.rowconfigure(0, weight=1)
        cols = ("tick", "camera", "change", "now", "new", "note")
        heads = ("", "Camera", "Change", "Now", "Will become", "Note")
        widths = (30, 150, 250, 80, 90, 260)
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="none")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="center" if c == "tick" else "w", stretch=c in ("change", "note"))
        self.tree.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.tag_configure("risky", foreground="#b3261e")
        self.tree.tag_configure("off", foreground="#888888")
        self.tree.bind("<Button-1>", self._click)
        self.lbl_info = ttk.Label(f, text="", wraplength=820, style="Warn.TLabel", justify="left")
        self.lbl_info.grid(row=3, column=0, sticky="w", pady=(6, 0))

        bf = ttk.Frame(f)
        bf.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(bf, text="Tick all", command=lambda: self._set_all(True)).pack(side="left")
        ttk.Button(bf, text="Untick all", command=lambda: self._set_all(False)).pack(side="left", padx=(6, 0))
        self.btn_apply = ttk.Button(bf, text="Apply", style="Big.TButton", command=self.apply)
        self.btn_apply.pack(side="right")
        ttk.Button(bf, text="Cancel", command=self.win.destroy).pack(side="right", padx=(0, 8))
        self.refresh()
        try:
            self.win.grab_set()   # modal
        except tk.TclError:
            pass

    def refresh(self) -> None:
        self.plans = self.app._plans(self.var_profile.get())
        self.tree.delete(*self.tree.get_children())
        self.changes.clear()
        self.ticked.clear()
        for p in self.plans:
            for ch in p.changes:
                iid = f"{p.camera.host}|{ch.control_id}"
                self.changes[iid] = (p, ch)
                if len(ch.writes) == 1:
                    now, new = ch.writes[0].old, ch.writes[0].new
                    if len(str(new)) > 24:
                        now, new = "(current list)", "(secure list)"
                else:
                    now, new = f"{len(ch.writes)} settings", "hardened"
                notes = []
                if ch.disruptive:
                    notes.append("RISKY: can cut off access (ticked only if you choose)")
                if ch.requires_reboot:
                    notes.append("needs a camera restart to take effect")
                if ch.warning and not ch.disruptive:
                    notes.append(ch.warning)
                if not ch.disruptive:
                    self.ticked.add(iid)
                self.tree.insert("", "end", iid=iid, values=(
                    TICK if iid in self.ticked else UNTICK, p.camera.name or p.camera.host, ch.title,
                    now, new, "; ".join(notes)), tags=("risky",) if ch.disruptive else ())
        skipped = [f"{p.camera.label}: {reason}" for p in self.plans for cid, reason in p.skipped if cid == "*"]
        info = ""
        if not self.changes:
            info = "Nothing to fix with this option: every setting it covers is already correct."
        if skipped:
            info += ("\n" if info else "") + "Not included: " + "; ".join(skipped[:5])
        self.lbl_info.configure(text=info)
        self._update_button()

    def _click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        p, ch = self.changes[iid]
        if iid in self.ticked:
            self.ticked.discard(iid)
        else:
            if ch.disruptive and not messagebox.askyesno(
                    "Risky change", f"{ch.title}\n\n{ch.warning}\n\nOnly tick this if you are sure nothing still "
                    "needs the old setting. Include it?", parent=self.win):
                return
            self.ticked.add(iid)
        vals = list(self.tree.item(iid, "values"))
        vals[0] = TICK if iid in self.ticked else UNTICK
        tags = ("risky",) if ch.disruptive else ()
        self.tree.item(iid, values=vals, tags=tags if iid in self.ticked else tags + ("off",))
        self._update_button()

    def _set_all(self, on: bool) -> None:
        for iid, (p, ch) in self.changes.items():
            if on and ch.disruptive:
                continue   # risky ones must be ticked one by one
            (self.ticked.add if on else self.ticked.discard)(iid)
            vals = list(self.tree.item(iid, "values"))
            vals[0] = TICK if iid in self.ticked else UNTICK
            self.tree.item(iid, values=vals)
        self._update_button()

    def _update_button(self) -> None:
        n = len(self.ticked)
        self.btn_apply.configure(text=f"Apply {n} change(s)", state="normal" if n else "disabled")

    def apply(self) -> None:
        import copy as _copy
        chosen = []
        for p in self.plans:
            keep = [ch for ch in p.changes if f"{p.camera.host}|{ch.control_id}" in self.ticked]
            if keep:
                q = _copy.copy(p)
                q.changes = keep
                q.skipped = []
                chosen.append(q)
        n = sum(len(p.changes) for p in chosen)
        risky = [ch.title for p in chosen for ch in p.changes if ch.disruptive]
        msg = (f"Change {n} setting(s) on {len(chosen)} camera(s)?\n\n"
               "Each change is checked afterwards and recorded in the audit log. You can put things back with "
               "\"Undo last changes\".")
        if risky:
            msg += "\n\nIncludes RISKY changes: " + ", ".join(sorted(set(risky)))
        if self.app.factory is not None:
            msg += "\n\n(Demo: only the recorded demo cameras change. No real camera is touched.)"
        if not messagebox.askyesno("Apply changes", msg, icon="warning", parent=self.win):
            return
        profile = load_profile(self.var_profile.get(), self.app.catalog)
        self.win.destroy()
        self.app.start_apply(chosen, profile)


def run_gui(output_dir: str | None = None) -> int:
    if sys.platform.startswith("win"):
        try:  # crisp text on high-DPI screens
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    setup_logging(verbose=False)
    root = tk.Tk()
    App(root, output_dir=output_dir)
    root.mainloop()
    return 0
