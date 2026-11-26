"""Tkinter GUI for non-technical operators (standard library only).

One window, three steps: choose the camera list, fill in a few details, press Run. After a check,
"Fix problems..." previews every change with a tick box; nothing is written until the user confirms.
"Undo last changes" restores the previous values. Credentials stay in memory exactly as in the CLI.
"""

from __future__ import annotations

import dataclasses
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
from .. import accounts as acc
from ..apply import build_rollback, make_plan, run_apply, run_rollback
from ..audit import AuditSettings, CameraResult, load_fixture_cameras, run_audit, simulated_factory
from ..catalog import (BUILTIN_PROFILES, CatalogError, list_profiles, load_catalog, load_profile, profile_slug,
                       resource_dir, save_profile, user_profiles_dir)
from ..evaluate import NON_COMPLIANT, compliance_pct
from ..inventory import Camera, Credential, InventoryError, NewAccount, load_inventory, password_findings, write_templates
from ..vapix import users as vusers
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
# Disruptive controls that do NOT need the extra tick-and-confirm step. HTTPS only (AX-B-009): apply checks HTTPS
# works before writing it and reconnects over HTTPS afterwards, so it is ticked like any other change.
NO_EXTRA_CONFIRM = {"AX-B-009"}
HTTPS_NOTE = "camera will answer on HTTPS only: anything using http:// (e.g. the VMS) must use https://"


def needs_extra_confirm(item) -> bool:
    """True for risky changes/controls that start unticked and must be confirmed one by one."""
    cid = getattr(item, "control_id", None) or getattr(item, "id", "")
    return bool(item.disruptive) and cid not in NO_EXTRA_CONFIRM


MARKINGS = ["", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]


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
        self.last_apply_dir: Path | None = None     # last apply or accounts run (for "Undo last changes")
        self.last_change_kind = "apply"             # apply | accounts
        self.restart_hosts: list[str] = []          # cameras whose last changes need a restart
        self.last_account_cams: list[Camera] = []   # cameras + new accounts of the last account run (memory only)
        self.saved_logins: dict[str, Credential] = {}  # host -> login removed by the last account run
        self._mode = "audit"                        # what the worker is doing: audit | apply | rollback | accounts...

        self.var_inventory = tk.StringVar(value="No camera list chosen yet")
        self.var_summary = tk.StringVar()
        self.var_operator = tk.StringVar()
        self.var_marking = tk.StringVar()
        self.var_baseline = tk.StringVar()          # label shown in "Check against"
        self.baseline_name = "audit-only"           # profile the last check was scored against
        self.var_customer = tk.StringVar()          # free text, goes on the report
        self.var_site_name = tk.StringVar()
        self.var_tls = tk.StringVar(value="verify")
        self.var_ca = tk.StringVar()
        self.var_output = tk.StringVar(value=str(Path(output_dir) if output_dir else app_dir() / "output"))
        self.var_progress_text = tk.StringVar(value="")

        self._load_settings()
        self._build()
        self._fill_baselines()
        self.root.after(100, self._poll)

    # ------------------------------------------------------------------ profiles
    @property
    def profiles_dir(self) -> Path:
        return user_profiles_dir(self.var_output.get())

    def load_profile(self, name: str):
        return load_profile(name, self.catalog, extra_dirs=[self.profiles_dir])

    def all_profiles(self):
        return list_profiles(self.catalog, [self.profiles_dir])

    EVERYTHING = "Everything: every control in the hardening guide (no baseline)"

    def scored(self, results):
        """Results as scored against the baseline of the last check (outside it = not counted)."""
        from ..evaluate import baseline_view
        return baseline_view(results, getattr(self, "baseline_ids", None), getattr(self, "baseline_name", ""))

    def _fill_baselines(self) -> None:
        """'Check against' choices: every control, then the profiles (built-in and custom)."""
        current = self._baseline_choice() if self.var_baseline.get() else getattr(self, "_saved_baseline", "")
        self.baseline_labels = {self.EVERYTHING: "audit-only"}
        for p in self.all_profiles():
            if p.name not in ("audit-only", "factory-defaults"):
                self.baseline_labels[profile_label(p)] = p.name
        self.cmb_baseline.configure(values=list(self.baseline_labels))
        label = next((lbl for lbl, n in self.baseline_labels.items() if n == current), self.EVERYTHING)
        self.var_baseline.set(label)

    def _baseline_choice(self) -> str:
        return getattr(self, "baseline_labels", {}).get(self.var_baseline.get(), "audit-only")

    def open_profiles(self, start: str | None = None, on_close=None) -> "ProfileEditor":
        return ProfileEditor(self, start=start, on_close=on_close)

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
        self.var_customer.set(s.get("customer", ""))
        self.var_site_name.set(s.get("site_name", ""))
        self._saved_baseline = s.get("baseline", "")
        self.var_marking.set(s.get("marking", ""))
        if s.get("tls") in TLS_MODES:
            self.var_tls.set(s["tls"])
        self.var_ca.set(s.get("ca_bundle", ""))

    def _save_settings(self) -> None:
        data = {"operator": self.var_operator.get(), "customer": self.var_customer.get(),
                "site_name": self.var_site_name.get(), "baseline": self._baseline_choice(),
                "marking": self.var_marking.get(),
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
        # Treeview rows have a fixed pixel height that does not follow Windows display scaling, so rows get cut
        # off at 125-200 %. Size them from the real font height instead.
        import tkinter.font as tkfont
        line = max(tkfont.nametofont(n).metrics("linespace") for n in ("TkDefaultFont", "TkTextFont"))
        style.configure("Treeview", rowheight=int(line * 1.4) + 6)
        style.configure("Treeview.Heading", padding=(4, 4))

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
        ttk.Button(s1, text="Make a blank camera list (template)...", command=self.make_template).grid(row=0, column=2, padx=(6, 0))
        ttk.Label(s1, textvariable=self.var_summary).grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.lbl_warn = ttk.Label(s1, text="", style="Warn.TLabel", wraplength=820, justify="left")
        self.lbl_warn.grid(row=2, column=0, columnspan=3, sticky="w")

        # Step 2
        s2 = ttk.LabelFrame(outer, text="  2. Details  ", style="Step.TLabelframe", padding=10)
        s2.grid(row=3, column=0, sticky="ew", pady=10)
        s2.columnconfigure(1, weight=1)
        ttk.Label(s2, text="Your name").grid(row=0, column=0, sticky="w")
        ttk.Entry(s2, textvariable=self.var_operator, width=34).grid(row=0, column=1, sticky="w", pady=2)
        ttk.Label(s2, text="Customer").grid(row=1, column=0, sticky="w")
        self.ent_customer = ttk.Entry(s2, textvariable=self.var_customer, width=34)
        self.ent_customer.grid(row=1, column=1, sticky="w", pady=2)
        ttk.Label(s2, text="Site name").grid(row=2, column=0, sticky="w")
        self.ent_site = ttk.Entry(s2, textvariable=self.var_site_name, width=34)
        self.ent_site.grid(row=2, column=1, sticky="w", pady=2)
        ttk.Label(s2, text="Check against").grid(row=3, column=0, sticky="w")
        bf2 = ttk.Frame(s2)
        bf2.grid(row=3, column=1, sticky="w", pady=2)
        self.cmb_baseline = ttk.Combobox(bf2, textvariable=self.var_baseline, state="readonly", width=70)
        self.cmb_baseline.pack(side="left")
        ttk.Button(bf2, text="Profiles...", command=lambda: self.open_profiles(
            start=self._baseline_choice(), on_close=lambda _saved: self._fill_baselines())).pack(side="left", padx=(6, 0))
        ttk.Label(s2, text="Report marking").grid(row=4, column=0, sticky="w")
        ttk.Combobox(s2, textvariable=self.var_marking, values=MARKINGS, width=31).grid(row=4, column=1, sticky="w", pady=2)
        ttk.Label(s2, text="Certificates").grid(row=5, column=0, sticky="nw", pady=(4, 0))
        tls = ttk.Frame(s2)
        tls.grid(row=5, column=1, sticky="w", pady=(4, 0))
        for i, (key, text) in enumerate(TLS_MODES.items()):
            ttk.Radiobutton(tls, text=text, value=key, variable=self.var_tls,
                            command=self._tls_changed).grid(row=i, column=0, sticky="w")
        caf = ttk.Frame(tls)
        caf.grid(row=1, column=1, sticky="w", padx=(8, 0))
        self.ent_ca = ttk.Entry(caf, textvariable=self.var_ca, width=30)
        self.ent_ca.pack(side="left")
        self.btn_ca = ttk.Button(caf, text="Browse...", command=self.choose_ca)
        self.btn_ca.pack(side="left", padx=(4, 0))
        ttk.Label(s2, text="Save reports in").grid(row=6, column=0, sticky="w", pady=(6, 0))
        outf = ttk.Frame(s2)
        outf.grid(row=6, column=1, sticky="ew", pady=(6, 0))
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
        self.btn_accounts = ttk.Button(bf, text="Create accounts...", command=self.open_accounts, state="disabled")
        self.btn_accounts.pack(side="left", padx=(6, 0))
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
        f.add_separator()
        f.add_command(label="Exit", command=self.root.destroy)
        m.add_cascade(label="File", menu=f)
        t = tk.Menu(m, tearoff=False)
        t.add_command(label="Try a demo (no cameras needed)", command=self.run_demo)
        t.add_command(label="Hardening profiles (choose what can be changed)...", command=self.open_profiles)
        t.add_command(label="Restart cameras...", command=self.restart_cameras)
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
        customers = sorted({c.customer for c in cams if c.customer})
        if len(customers) == 1 and not self.var_customer.get().strip():
            self.var_customer.set(customers[0])          # pre-fill from the camera list's customer column
        self.var_summary.set(f"{len(cams)} camera(s) loaded" +
                             (f" for {len(customers)} customer(s)" if len(customers) > 1 else
                              (f" for {customers[0]}" if customers else "")))
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
            for b in (self.btn_report, self.btn_folder, self.btn_fix, self.btn_undo, self.btn_accounts):
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
        cams = list(self.cameras)
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
            messagebox.showinfo("No cameras", "The camera list is empty.", parent=self.root)
            return
        for c in cams:
            if self.tree.exists(c.host):
                self.tree.item(c.host, values=(c.name or c.host, c.address, "", "", "Checking...", "", ""), tags=())
        self.results.clear()
        self.progress.configure(maximum=len(cams), value=0)
        self.var_progress_text.set(f"Checking {len(cams)} camera(s)...")
        self._busy(True)
        settings = AuditSettings(tls=tls, operator=self.var_operator.get().strip() or "(demo)",
                                 customer=self.var_customer.get().strip(), site_name=self.var_site_name.get().strip())
        marking = self.var_marking.get().strip()
        out = Path(self.var_output.get())
        pf = password_findings(cams) if factory is None else password_findings([])
        self.factory, self.settings, self.pf, self.audit_cams = factory, settings, pf, cams
        try:
            baseline = self.load_profile(self._baseline_choice())
        except CatalogError:
            baseline = self.load_profile("audit-only")
        self.baseline_name = baseline.name
        self.baseline_ids = None if baseline.name == "audit-only" else list(baseline.control_ids)
        self.last_apply_dir = None
        self._mode = "audit"

        def work() -> None:
            profile = baseline
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
        """A camera finished an apply/undo/accounts run."""
        self.results[r.camera["host"]] = r
        self.progress.step(1)
        done, total = int(self.progress["value"]), int(self.progress["maximum"])
        self.var_progress_text.set(f"Changed {done} of {total} camera(s)")
        changes = [c for c in r.changes if "writes" in c]
        ok = sum(c["status"] == "verified" for c in changes)
        bad = sum(c["status"] in ("failed", "skipped") for c in changes)
        if self._mode.startswith("accounts") and r.status == "OK":
            if self._mode == "accounts":
                made = [c for c in changes if c.get("kind") == acc.CH_CREATE]
                parts = [f"{sum(c['status'] == 'verified' for c in made)} created"]
                n_exist = sum(c["status"] == "skipped" for c in made)
                if n_exist:
                    parts.append(f"{n_exist} already existed")
                rm = next((c for c in changes if c.get("kind") == acc.CH_REMOVE_LOGIN), None)
                if rm is not None:
                    parts.append({"verified": "login account removed", "failed": "login account kept (refused)",
                                  "skipped": "login account kept"}.get(rm["status"], rm["status"]))
            else:
                gone = sum(c["status"] == "verified" for c in changes if c.get("kind") == acc.CH_REMOVE)
                parts = [f"{gone} removed"]
                if any(c.get("kind") == acc.CH_RESTORE and c["status"] == "verified" for c in changes):
                    parts.insert(0, "login account back")
            bad = sum(c["status"] == "failed" for c in changes)
            result = ", ".join(parts) + (f", {bad} failed" if bad else "")
        elif self._mode == "restart":
            ch = r.changes[0] if r.changes else {}
            result = {"verified": "Restarted", "failed": "Did not come back!"}.get(
                ch.get("status"), STATUS_LABEL.get(r.status, r.status))
            bad = int(ch.get("status") != "verified")
        elif r.status == "LOST_CONTACT":
            result = "Lost contact!"
        elif r.status != "OK":
            result = STATUS_LABEL.get(r.status, r.status)
        else:
            result = f"{ok} changed" + (f", {bad} failed" if bad else "")
        final = self.scored(r.after or r.results)
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
            fixable = self._plans(self.baseline_name if self.baseline_name != "audit-only" else "basic-full")
            n = sum(not ch.revert for p in fixable for ch in p.changes)
            if any(r.status == "OK" for r in results):
                self.btn_fix.configure(state="normal")   # a custom profile may cover more than basic-full
                self.btn_accounts.configure(state="normal")
            if n:
                text += f"\n{n} problem(s) can be fixed automatically: click \"Fix problems...\"."
            title = "Check finished"
        elif kind.startswith("accounts"):
            changes = [c for r in results for c in r.changes if "writes" in c]
            ok = sum(c["status"] == "verified" for c in changes)
            skipped = [c for c in changes if c["status"] == "skipped"]
            failed = [c for c in changes if c["status"] == "failed"]
            unreachable = [r for r in results if r.status != "OK"]
            if kind == "accounts":
                created = [c for c in changes if c.get("kind") == acc.CH_CREATE]
                ok = sum(c["status"] == "verified" for c in created)
                skipped = [c for c in created if c["status"] == "skipped"]
                failed = [c for c in changes if c["status"] == "failed"]
                text = f"Created and verified {ok} account(s)."
                if skipped:
                    text += f" {len(skipped)} already existed and were left unchanged."
                text += self._swap_logins(results)
                self.last_apply_dir, self.last_change_kind = run_dir, "accounts"
                if ok or failed:
                    self.btn_undo.configure(state="normal")
            else:
                removed = sum(c["status"] == "verified" for c in changes if c.get("kind") == acc.CH_REMOVE)
                text = f"Removed {removed} account(s)."
                back = [r.camera["host"] for r in results for c in r.changes
                        if c.get("kind") == acc.CH_RESTORE and c["status"] in ("verified", "skipped")]
                for host in back:
                    self._set_login(host, self.saved_logins.pop(host, None))
                if back:
                    text += f" The original login account is back on {len(back)} camera(s)."
            if failed:
                text += f" {len(failed)} failed (see the report)."
            if unreachable:
                text += f" {len(unreachable)} camera(s) could not be reached."
            title = "Accounts finished" if kind == "accounts" else "Undo finished"
            if self.audit_results:
                self.btn_accounts.configure(state="normal")
        elif kind == "restart":
            ok = [r for r in results if r.status == "OK" and r.changes and r.changes[0].get("status") == "verified"]
            text = f"Restarted {len(ok)} of {len(results)} camera(s); they answer again."
            bad = [r for r in results if r not in ok]
            if bad:
                text += (f"\nWARNING: {len(bad)} camera(s) did not come back or could not be restarted: "
                         f"{', '.join(r.camera.get('name') or r.camera['host'] for r in bad)}. Check them.")
            text += "\nRun the check again to confirm the result."
            title = "Restart finished"
            if self.last_apply_dir:
                self.btn_undo.configure(state="normal")       # a restart does not replace "Undo last changes"
            if self.audit_results:
                self.btn_fix.configure(state="normal")
                self.btn_accounts.configure(state="normal")
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
            from ..restart import needs_restart
            restart_hosts = needs_restart(results)
            if kind == "apply":
                self.last_apply_dir, self.last_change_kind = run_dir, "apply"
                self.btn_undo.configure(state="normal")
            if restart_hosts:
                self.restart_hosts = restart_hosts
                text += (f"\n{len(restart_hosts)} camera(s) need a restart before some changes (TLS ciphers) take "
                         "effect.")
            text += "\nRun the check again to confirm the result."
            title = "Changes finished" if kind == "apply" else "Undo finished"
        self.var_progress_text.set(text.replace("\n", "  "))
        if messagebox.askyesno(title, f"{text}\n\nOpen the report now?", parent=self.root):
            self.open_report()
        if kind in ("apply", "rollback") and self.restart_hosts:
            self.restart_cameras(self.restart_hosts)

    # ------------------------------------------------------------------ restarting cameras
    def _restart_candidates(self) -> list[Camera]:
        if self.restart_hosts:
            return [c for c in self.audit_cams if c.host in self.restart_hosts]
        ok = {r.camera["host"] for r in self.audit_results if r.status == "OK"}
        return [c for c in self.audit_cams if c.host in ok]

    def restart_cameras(self, hosts: list[str] | None = None) -> None:
        if self.worker and self.worker.is_alive():
            return
        cams = [c for c in self.audit_cams if c.host in hosts] if hosts else self._restart_candidates()
        if not cams:
            messagebox.showinfo("Restart cameras", "Run a check first: there are no checked cameras to restart.",
                                parent=self.root)
            return
        why = ("These cameras need a restart before the changes take effect"
               if hosts or self.restart_hosts else "Restart every checked camera")
        names = "\n".join(f"  {c.name or c.host} ({c.host})" for c in cams[:15]) + ("\n  ..." if len(cams) > 15 else "")
        msg = (f"{why}:\n\n{names}\n\nVideo and recording stop for about 1-3 minutes per camera. The program waits "
               "until each camera answers again.")
        if self.factory is not None:
            msg += "\n\n(Demo: only the recorded demo cameras restart. No real camera is touched.)"
        if not messagebox.askyesno(f"Restart {len(cams)} camera(s) now?", msg, icon="warning", parent=self.root):
            return
        self.start_restart(cams)

    def start_restart(self, cams: list[Camera]) -> None:
        from ..restart import run_restart
        self._mode = "restart"
        self.progress.configure(maximum=len(cams), value=0)
        self.var_progress_text.set(f"Restarting {len(cams)} camera(s) and waiting for them to come back...")
        for c in cams:
            if self.tree.exists(c.host):
                vals = list(self.tree.item(c.host, "values"))
                vals[4] = "Restarting..."
                self.tree.item(c.host, values=vals, tags=())
        self._busy(True)
        self.results.clear()
        marking = self.var_marking.get().strip()
        out = Path(self.var_output.get())
        wait = {"timeout": 10, "poll": 0.1, "down_wait": 0.1} if self.factory is not None else {}
        self.restart_hosts = []

        def work() -> None:
            _, run_dir, _ = run_restart(cams, self.catalog, self.settings, out, "gui", client_factory=self.factory,
                                        progress=lambda r: self.queue.put(("changed", r)),
                                        simulated=self.factory is not None, reason="gui", **wait)
            html, _, _ = write_reports(run_dir, self.catalog, marking)
            self.queue.put(("done", run_dir, html, "restart", None))

        self._run_worker(work)

    # ------------------------------------------------------------------ fixing problems (phase 2)
    def _plans(self, profile_name: str):
        if not self.audit_results:
            return []
        profile = self.load_profile(profile_name)
        by_host = {c.host for c in self.audit_cams}
        audits = [r for r in self.audit_results if r.camera["host"] in by_host]
        return make_plan(audits, self.audit_cams, self.catalog, profile, self.load_profile)

    def open_fix(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        if self.factory is None and time.monotonic() - self.audit_time > 30 * 60:
            if not messagebox.askyesno("Check is out of date", "The last check was more than 30 minutes ago. "
                                       "Camera settings may have changed since.\n\nContinue anyway? "
                                       "(Choose No and press \"Run check\" first.)", parent=self.root):
                return
        FixDialog(self)

    def open_accounts(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        AccountDialog(self)

    def start_accounts(self, cams: list[Camera], remove_login: bool = False) -> None:
        self._mode = "accounts"
        self.last_account_cams = list(cams)       # kept in memory so "Undo last changes" needs no passwords
        self.progress.configure(maximum=len(cams), value=0)
        self.var_progress_text.set(f"Creating accounts on {len(cams)} camera(s)...")
        for c in cams:
            if self.tree.exists(c.host):
                vals = list(self.tree.item(c.host, "values"))
                vals[4] = "Creating account..."
                self.tree.item(c.host, values=vals, tags=())
        self._busy(True)
        self.results.clear()
        marking = self.var_marking.get().strip()
        out = Path(self.var_output.get())

        def work() -> None:
            _, run_dir, _ = acc.run_create_accounts(cams, self.catalog, self.settings, out, "gui",
                                                    client_factory=self.factory,
                                                    progress=lambda r: self.queue.put(("changed", r)),
                                                    simulated=self.factory is not None, remove_login=remove_login)
            html, _, _ = write_reports(run_dir, self.catalog, marking)
            self.queue.put(("done", run_dir, html, "accounts", None))

        self._run_worker(work)

    def _set_login(self, host: str, cred: Credential | None) -> None:
        if cred is None:
            return
        for c in self.cameras + self.audit_cams:
            if c.host == host:
                c.credential = cred

    def _swap_logins(self, results) -> str:
        """After the login account was removed, log in as the new admin for the rest of this session."""
        moved = acc.login_changes(results)
        by_host = {c.host: c for c in self.last_account_cams}
        for host, user in moved.items():
            cam = by_host.get(host)
            new = next((a.credential for a in (cam.new_accounts if cam else []) if a.username == user), None)
            old = next((c.credential for c in self.cameras + self.audit_cams if c.host == host), None)
            if new is not None and old is not None:
                self.saved_logins[host] = old
                self._set_login(host, new)
        if not moved:
            return ""
        users = ", ".join(sorted(set(moved.values())))
        return (f"\n\nThe login account was removed on {len(moved)} camera(s). This program now logs in as {users} "
                "until it is closed. UPDATE THE CAMERA LIST: put the new Administrator account in the username and "
                "password columns, or the next check will fail with \"Wrong password\".")

    def _ask_undo_password(self, username: str, why: str) -> str | None:
        return simpledialog.askstring("Password needed", f"Type the password for '{username}' (needed to {why}):",
                                      show="*", parent=self.root)

    def _undo_accounts(self) -> None:
        try:
            by_host = {c.host: c for c in self.last_account_cams}
            cams = [by_host.get(c.host, c) for c in self.audit_cams]
            # cameras whose login was removed: the camera list now logs in as the new admin; undo needs the old one
            cams = [dataclasses.replace(c, credential=self.saved_logins[c.host]) if c.host in self.saved_logins
                    else c for c in cams]
            _, jobs = acc.build_account_undo(self.last_apply_dir, cams, ask=self._ask_undo_password)
        except ValueError as e:
            messagebox.showerror("Cannot undo", str(e), parent=self.root)
            return
        if not jobs:
            messagebox.showinfo("Nothing to undo", "No accounts were created in the last run.", parent=self.root)
            return
        names = sorted({u for j in jobs for u in j.remove})
        msg = (f"Remove the account(s) {', '.join(names)} from {len(jobs)} camera(s)? Only accounts created by the "
               "last run are removed.")
        restored = sorted({j.restore["username"] for j in jobs if j.restore})
        if restored:
            msg += (f"\n\nThe login account ({', '.join(restored)}) is put back first, with its old password, and "
                    "checked before anything is removed.")
        if not messagebox.askyesno("Undo last changes", msg, parent=self.root):
            return
        self._mode = "accounts-undo"
        self.progress.configure(maximum=len(jobs), value=0)
        self._busy(True)
        self.results.clear()
        marking = self.var_marking.get().strip()
        out = Path(self.var_output.get())
        run_dir_in = self.last_apply_dir

        def work() -> None:
            _, run_dir, _ = acc.run_account_undo(run_dir_in, jobs, self.catalog, self.settings, out, "gui",
                                                 client_factory=self.factory,
                                                 progress=lambda r: self.queue.put(("changed", r)),
                                                 simulated=self.factory is not None)
            html, _, _ = write_reports(run_dir, self.catalog, marking)
            self.queue.put(("done", run_dir, html, "accounts-undo", None))

        self.last_apply_dir = None
        self._run_worker(work)

    def start_apply(self, plans, profile) -> None:
        self._mode = "apply"
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
        if self.last_change_kind == "accounts":
            self._undo_accounts()
            return
        self._mode = "rollback"
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
            "   No list yet? Use \"Make a blank camera list (template)\". Leave passwords empty and the tool will ask for them.\n\n"
            "2. Details: type your name. Pick a report marking if your organisation needs one.\n"
            "   If cameras show \"Certificate problem\", choose \"Accept the cameras' own certificates\".\n\n"
            "3. Press Run check. When it finishes, open the report.\n\n"
            "Checking only reads settings. Cameras change only if you press \"Fix problems...\" and confirm.\n"
            "Tools > Hardening profiles lets you choose which settings \"Fix problems...\" may change.\n"
            "Passwords are never saved.\n"
            "Want to see what it does first? Tools > Try a demo."), parent=self.root)

    def show_about(self) -> None:
        messagebox.showinfo("About", f"{APP_TITLE}\naxharden {__version__}\n\nChecks against the {GUIDE_REF}.\n"
                            f"Catalog SHA-256: {self.catalog.sha256[:16]}...", parent=self.root)


FIX_PROFILES = {
    "basic-safe": "Recommended changes (safe for normal use)",
    "basic-full": "Recommended + turn off the web interface and hide the server version (Axis's full hardening)",
}
TICK, UNTICK = "☑", "☐"


def profile_label(p) -> str:
    if p.name in FIX_PROFILES:
        return "Axis recommended: " + FIX_PROFILES[p.name]
    if p.builtin:
        return BUILTIN_PROFILES.get(p.name, p.name)
    return f"Custom: {p.name}" + (f" - {p.description}" if p.description else "")


class FixDialog:
    """Preview of every change, with a tick box per change. Nothing is written until the user confirms."""

    def __init__(self, app: "App"):
        self.app = app
        self.win = tk.Toplevel(app.root)
        self.win.title("Fix problems")
        self.win.transient(app.root)
        self.win.minsize(860, 480)
        self.var_profile = tk.StringVar(value=app.baseline_name if app.baseline_name != "audit-only" else "basic-safe")
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
        pf.grid(row=1, column=0, sticky="ew", pady=8)
        pf.columnconfigure(1, weight=1)
        ttk.Label(pf, text="Which changes:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.var_label = tk.StringVar()
        self.cmb_profile = ttk.Combobox(pf, textvariable=self.var_label, state="readonly", width=90)
        self.cmb_profile.grid(row=0, column=1, sticky="ew")
        self.cmb_profile.bind("<<ComboboxSelected>>", self._profile_chosen)
        ttk.Button(pf, text="Edit profiles...", command=self._edit_profiles).grid(row=0, column=2, padx=(6, 0))
        self._fill_profiles()

        tf = ttk.Frame(f)
        tf.grid(row=2, column=0, sticky="nsew")
        tf.columnconfigure(0, weight=1)
        tf.rowconfigure(0, weight=1)
        cols = ("tick", "camera", "change", "now", "new", "note")
        heads = ("", "Camera", "Change", "Now", "Will become", "Note")
        widths = (30, 140, 260, 130, 160, 220)
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="none")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="center" if c == "tick" else "w", stretch=c in ("change", "note"))
        self.tree.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.tag_configure("risky", foreground="#b3261e")
        self.tree.tag_configure("revert", foreground="#9a5b00")
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

    def _fill_profiles(self) -> None:
        profs = [p for p in self.app.all_profiles() if p.name != "audit-only"]
        self.labels = {profile_label(p): p.name for p in profs}
        self.cmb_profile.configure(values=list(self.labels))
        if self.var_profile.get() not in self.labels.values():
            self.var_profile.set("basic-safe")
        self.var_label.set(next((lbl for lbl, n in self.labels.items() if n == self.var_profile.get()), ""))

    def _profile_chosen(self, _event=None) -> None:
        self.var_profile.set(self.labels[self.var_label.get()])
        self.refresh()

    def _edit_profiles(self) -> None:
        try:
            self.win.grab_release()
        except tk.TclError:
            pass

        def closed(saved: str | None) -> None:
            if not self.win.winfo_exists():
                return
            if saved:
                self.var_profile.set(saved)
            self._fill_profiles()
            self.refresh()
            try:
                self.win.grab_set()
            except tk.TclError:
                pass
        self.app.open_profiles(start=self.var_profile.get(), on_close=closed)

    def refresh(self) -> None:
        try:
            self.plans = self.app._plans(self.var_profile.get())
        except CatalogError as e:
            messagebox.showerror("Profile problem", str(e), parent=self.win)
            self.var_profile.set("basic-safe")
            self._fill_profiles()
            self.plans = self.app._plans("basic-safe")
        self.tree.delete(*self.tree.get_children())
        self.changes.clear()
        self.ticked.clear()
        for p in self.plans:
            for ch in p.changes:
                iid = f"{p.camera.host}|{ch.control_id}"
                self.changes[iid] = (p, ch)
                now, new = ch.now_label, ch.new_label       # plain words, e.g. "Enabled" -> "Disabled"
                if not (now and new):
                    now, new = (ch.writes[0].old, ch.writes[0].new) if len(ch.writes) == 1 else \
                        (f"{len(ch.writes)} settings", "changed")
                notes = []
                risky = needs_extra_confirm(ch)
                if risky:
                    notes.append("RISKY: can cut off access (ticked only if you choose)")
                elif ch.control_id in NO_EXTRA_CONFIRM and not ch.revert:
                    notes.append(HTTPS_NOTE)
                if ch.requires_reboot:
                    notes.append("needs a camera restart to take effect")
                if ch.warning and not ch.disruptive:
                    notes.append(ch.warning)
                if not risky:
                    self.ticked.add(iid)
                self.tree.insert("", "end", iid=iid, values=(
                    TICK if iid in self.ticked else UNTICK, p.camera.name or p.camera.host, ch.title,
                    now, new, "; ".join(notes)), tags=("risky",) if risky else (("revert",) if ch.revert else ()))
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
            if needs_extra_confirm(ch) and not messagebox.askyesno(
                    "Risky change", f"{ch.title}\n\n{ch.warning}\n\nOnly tick this if you are sure nothing still "
                    "needs the old setting. Include it?", parent=self.win):
                return
            self.ticked.add(iid)
        vals = list(self.tree.item(iid, "values"))
        vals[0] = TICK if iid in self.ticked else UNTICK
        tags = ("risky",) if needs_extra_confirm(ch) else (("revert",) if ch.revert else ())
        self.tree.item(iid, values=vals, tags=tags if iid in self.ticked else tags + ("off",))
        self._update_button()

    def _set_all(self, on: bool) -> None:
        for iid, (p, ch) in self.changes.items():
            if on and needs_extra_confirm(ch):
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
        risky = [ch.title for p in chosen for ch in p.changes if needs_extra_confirm(ch)]
        https = any(ch.control_id in NO_EXTRA_CONFIRM and not ch.revert for p in chosen for ch in p.changes)
        msg = (f"Change {n} setting(s) on {len(chosen)} camera(s)?\n\n"
               "Each change is checked afterwards and recorded in the audit log. You can put things back with "
               "\"Undo last changes\".")
        reverts = sum(ch.revert for p in chosen for ch in p.changes)
        if reverts:
            msg += (f"\n\n{reverts} change(s) put settings back to the AXIS OS factory default because they are not "
                    "in this profile. This makes those cameras LESS SECURE. Untick them to leave them as they are.")
        if https:
            msg += "\n\nIncludes HTTPS only: the " + HTTPS_NOTE + "."
        if risky:
            msg += "\n\nIncludes RISKY changes: " + ", ".join(sorted(set(risky)))
        if self.app.factory is not None:
            msg += "\n\n(Demo: only the recorded demo cameras change. No real camera is touched.)"
        if not messagebox.askyesno("Apply changes", msg, icon="warning", parent=self.win):
            return
        profile = self.app.load_profile(self.var_profile.get())
        self.win.destroy()
        self.app.start_apply(chosen, profile)


EDITOR_GROUPS = [
    ("default", "Default protection (on by default in newer AXIS OS)"),
    ("basic", "Basic hardening (guide pp.32-34)"),
    ("legacy", "Older AXIS OS only (feature removed in later versions)"),
    ("extended", "Extended hardening"),
    ("check", "Checks (read only: counted in the score when checking against this profile, never changed)"),
]

LEVEL_GROUPS = [
    ("default", "Default protection (on by default in newer AXIS OS)"),
    ("basic", "Basic hardening (guide pp.32-34)"),
    ("legacy", "Older AXIS OS only (feature removed in later versions)"),
    ("extended", "Extended hardening"),
]


class ProfileEditor:
    """Choose which hardening changes a profile makes. The built-in (Axis-recommended) profiles are read-only;
    Save writes a custom profile to <reports folder>/profiles/<name>.yaml, usable from the GUI and the CLI."""

    def __init__(self, app: "App", start: str | None = None, on_close=None):
        self.app = app
        self.on_close = on_close
        self.saved: str | None = None
        self.controls = list(app.catalog.controls)      # changeable settings and read-only checks
        self.by_id = {c.id: c for c in self.controls}
        self.ticked: set[str] = set()
        self.current = None      # Profile being shown (None = new blank)
        self.dirty = False

        self.win = tk.Toplevel(app.root)
        self.win.title("Hardening profiles")
        self.win.transient(app.root)
        self.win.minsize(920, 580)
        self.win.protocol("WM_DELETE_WINDOW", self.close)
        f = ttk.Frame(self.win, padding=12)
        f.pack(fill="both", expand=True)
        f.columnconfigure(0, weight=1)
        f.rowconfigure(4, weight=1)

        ttk.Label(f, text="A profile is the list of settings \"Fix problems...\" may change, and the checks a camera is "
                  "scored against when you choose it under \"Check against\". The Axis-recommended profiles come "
                  "from the hardening guide and cannot be edited. To make your own, start from one, tick or "
                  "untick settings and checks, type a new name and press Save.", wraplength=880, justify="left").grid(
            row=0, column=0, sticky="w")

        top = ttk.Frame(f)
        top.grid(row=1, column=0, sticky="ew", pady=(10, 4))
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Profile:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.var_choice = tk.StringVar()
        self.cmb = ttk.Combobox(top, textvariable=self.var_choice, state="readonly", width=80)
        self.cmb.grid(row=0, column=1, sticky="ew")
        self.cmb.bind("<<ComboboxSelected>>", self._chosen)
        ttk.Button(top, text="New blank", command=self.new_blank).grid(row=0, column=2, padx=(6, 0))
        self.btn_delete = ttk.Button(top, text="Delete", command=self.delete)
        self.btn_delete.grid(row=0, column=3, padx=(6, 0))

        meta = ttk.Frame(f)
        meta.grid(row=2, column=0, sticky="ew")
        meta.columnconfigure(1, weight=1)
        self.var_name = tk.StringVar()
        self.var_desc = tk.StringVar()
        ttk.Label(meta, text="Name").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(meta, textvariable=self.var_name, width=40).grid(row=0, column=1, sticky="w", pady=2)
        ttk.Label(meta, text="Description").grid(row=1, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(meta, textvariable=self.var_desc).grid(row=1, column=1, sticky="ew", pady=2)
        self.lbl_info = ttk.Label(f, text="", style="Warn.TLabel", wraplength=880, justify="left")
        self.lbl_info.grid(row=3, column=0, sticky="w", pady=(4, 4))

        tf = ttk.Frame(f)
        tf.grid(row=4, column=0, sticky="nsew")
        tf.columnconfigure(0, weight=1)
        tf.rowconfigure(0, weight=1)
        cols = ("tick", "id", "title", "page", "note")
        heads = ("", "ID", "Setting", "Guide p.", "Note")
        widths = (30, 80, 300, 60, 400)
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="none")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="center" if c in ("tick", "page") else "w",
                             stretch=c in ("title", "note"))
        self.tree.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.tag_configure("group", font=("Segoe UI", 9, "bold"), background="#eef1f5")
        self.tree.tag_configure("risky", foreground="#b3261e")
        self.tree.tag_configure("na", foreground="#999999")
        self.tree.bind("<Button-1>", self._click)
        self._build_rows()

        bf = ttk.Frame(f)
        bf.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(bf, text="Tick all recommended", command=self.tick_safe).pack(side="left")
        ttk.Button(bf, text="Untick all", command=self.untick_all).pack(side="left", padx=(6, 0))
        self.lbl_count = ttk.Label(bf, text="", style="Muted.TLabel")
        self.lbl_count.pack(side="left", padx=(12, 0))
        ttk.Button(bf, text="Close", command=self.close).pack(side="right")
        self.btn_save = ttk.Button(bf, text="Save", style="Big.TButton", command=self.save)
        self.btn_save.pack(side="right", padx=(0, 8))

        self._fill_choices(start or "basic-safe")
        # trace after the first fill so loading a profile does not count as an edit
        self.var_name.trace_add("write", lambda *_: self._mark_dirty())
        self.var_desc.trace_add("write", lambda *_: self._mark_dirty())
        try:
            self.win.grab_set()
        except tk.TclError:
            pass

    # ---------------------------------------------------------------- rows
    @staticmethod
    def _available(ctl) -> bool:
        return ctl.handler != "network_ports"     # network port controls: phase 3

    @staticmethod
    def _group(ctl) -> str:
        return "check" if ctl.kind == "check" else ctl.level

    def _note(self, ctl) -> str:
        if ctl.kind == "check":
            return self._fix_hint(ctl)
        if not self._available(ctl):
            return "Not available yet (network port controls come in a later version)"
        notes = []
        if needs_extra_confirm(ctl):
            notes.append("RISKY: can cut off access")
        elif ctl.id in NO_EXTRA_CONFIRM:
            notes.append(HTTPS_NOTE)
        if ctl.opt_in and not ctl.disruptive:
            notes.append("optional: only if not used")
        if ctl.requires_reboot:
            notes.append("needs restart")
        if ctl.introduced_in:
            notes.append(f"AXIS OS {ctl.introduced_in}+")
        if ctl.removed_in:
            notes.append(f"before AXIS OS {ctl.removed_in} only")
        if ctl.warning:
            notes.append(ctl.warning)
        return "; ".join(notes)

    def _build_rows(self) -> None:
        for level, label in EDITOR_GROUPS:
            ctls = [c for c in self.controls if self._group(c) == level]
            if not ctls:
                continue
            self.tree.insert("", "end", iid=f"group:{level}", values=("", "", label, "", "click to tick/untick the group"),
                             tags=("group",))
            for c in ctls:
                tags = ("na",) if not self._available(c) else (("risky",) if needs_extra_confirm(c) else ())
                self.tree.insert("", "end", iid=c.id, values=(UNTICK, c.id, c.title, c.guide_page, self._note(c)),
                                 tags=tags)

    def _render(self) -> None:
        for c in self.controls:
            vals = list(self.tree.item(c.id, "values"))
            vals[0] = TICK if c.id in self.ticked else UNTICK
            if c.kind == "check":
                vals[4] = self._note(c)
            self.tree.item(c.id, values=vals)
        for level, _ in EDITOR_GROUPS:
            gid = f"group:{level}"
            if self.tree.exists(gid):
                ids = [c.id for c in self.controls if self._group(c) == level and self._available(c)]
                on = sum(i in self.ticked for i in ids)
                vals = list(self.tree.item(gid, "values"))
                vals[0] = TICK if ids and on == len(ids) else ("▣" if on else UNTICK)
                self.tree.item(gid, values=vals)
        n = len(self.ticked)
        risky = sum(needs_extra_confirm(self.by_id[i]) for i in self.ticked)
        total = sum(map(self._available, self.controls))
        n_chk = sum(self.by_id[i].kind == "check" for i in self.ticked)
        t_chk = sum(c.kind == "check" for c in self.controls)
        self.lbl_count.configure(text=f"{n - n_chk} of {total - t_chk} settings and {n_chk} of {t_chk} checks ticked"
                                 + (f" ({risky} risky)" if risky else ""))

    # ---------------------------------------------------------------- choosing a profile
    def _fill_choices(self, select: str | None) -> None:
        self.profiles = {}
        for p in self.app.all_profiles():
            if p.name == "audit-only":
                continue
            self.profiles[profile_label(p)] = p
        self.cmb.configure(values=list(self.profiles))
        match = next((lbl for lbl, p in self.profiles.items() if p.name == select), None)
        if match is None and self.profiles:
            match = next(iter(self.profiles))
        if match:
            self.var_choice.set(match)
            self._show(self.profiles[match])

    def _chosen(self, _event=None) -> None:
        if not self._discard_ok():
            back = next((lbl for lbl, p in self.profiles.items() if self.current and p.name == self.current.name), "")
            self.var_choice.set(back)
            return
        self._show(self.profiles[self.var_choice.get()])

    def _show(self, prof) -> None:
        self.current = prof
        self.ticked = {i for i in prof.control_ids if i in self.by_id and self._available(self.by_id[i])}
        self.var_name.set(prof.name)
        self.var_desc.set(prof.description)
        if prof.builtin:
            self.lbl_info.configure(text="Axis-recommended profile from the hardening guide: it cannot be changed. "
                                    "Edit the ticks and press Save to keep a copy under a new name.")
        else:
            self.lbl_info.configure(text=f"Custom profile, saved in {prof.path}")
        self.btn_delete.configure(state="disabled" if prof.builtin else "normal")
        self._render()
        self.dirty = False

    def new_blank(self) -> None:
        if not self._discard_ok():
            return
        self.current = None
        self.ticked = set()
        self.var_choice.set("")
        self.var_name.set("")
        self.var_desc.set("")
        self.lbl_info.configure(text="New profile: tick the settings it may change, give it a name and press Save.")
        self.btn_delete.configure(state="disabled")
        self._render()
        self.dirty = False

    # ---------------------------------------------------------------- editing
    def _mark_dirty(self) -> None:
        self.dirty = True

    def _changed(self) -> None:
        self.dirty = True
        self._render()

    def _fix_hint(self, ctl) -> str:
        """How a read-only check is fixed: the setting to tick, the camera-list column, or what to do instead."""
        should = f"Should be {ctl.expect}. " if ctl.expect else ""
        fix = self.by_id.get(ctl.fix_control) if ctl.fix_control else None
        if fix is not None:
            where = "Basic hardening" if fix.level in ("basic", "default") else "Extended hardening"
            state = "ticked" if fix.id in self.ticked else f"tick it under {where}"
            return f"{should}Fixed by {fix.id} {fix.title} ({state})"
        if ctl.fix_column:
            return f"{should}Set per camera: '{ctl.fix_column}' column in the camera list (applied by Fix problems)"
        return should + (ctl.fix_text or "Report only")

    def toggle(self, cid: str, confirm: bool = True) -> None:
        ctl = self.by_id.get(cid)
        if ctl is None or not self._available(ctl):
            return
        if cid in self.ticked:
            self.ticked.discard(cid)
        else:
            if confirm and needs_extra_confirm(ctl) and not messagebox.askyesno(
                    "Risky setting", f"{ctl.title}\n\n{ctl.warning or ''}\n\nAdd this to the profile? In "
                    "\"Fix problems...\" it still starts unticked and has to be confirmed.", parent=self.win):
                return
            self.ticked.add(cid)
            fix = self.by_id.get(ctl.fix_control) if ctl.kind == "check" and ctl.fix_control else None
            if confirm and fix is not None and fix.id not in self.ticked and self._available(fix) and \
                    messagebox.askyesno("Fix it too?", f"{ctl.id} {ctl.title} is only checked.\n\n"
                                        f"Also tick {fix.id} {fix.title}, so \"Fix problems...\" can change it?"
                                        + (f"\n\nNote: {fix.warning}" if fix.warning else ""), parent=self.win):
                self.toggle(fix.id, confirm=True)
                return
        self._changed()

    def _click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid.startswith("group:"):
            level = iid.split(":", 1)[1]
            ids = [c.id for c in self.controls if self._group(c) == level and self._available(c)]
            safe = [i for i in ids if not needs_extra_confirm(self.by_id[i])]
            if all(i in self.ticked for i in safe):
                self.ticked.difference_update(ids)
            else:
                self.ticked.update(safe)          # risky ones must be ticked one by one
            self._changed()
            return
        self.toggle(iid)

    def tick_safe(self) -> None:
        self.ticked.update(c.id for c in self.controls if self._available(c) and not needs_extra_confirm(c) and not c.opt_in)
        self._changed()

    def untick_all(self) -> None:
        self.ticked.clear()
        self._changed()

    # ---------------------------------------------------------------- save / delete / close
    def save(self) -> bool:
        name = self.var_name.get().strip()
        if self.current is not None and self.current.builtin and profile_slug(name) in BUILTIN_PROFILES:
            name = simpledialog.askstring("Save as a new profile",
                                          "Axis-recommended profiles cannot be changed.\nName for your own copy:",
                                          initialvalue=f"{self.current.name}-custom", parent=self.win)
            if not name:
                return False
        if not self.ticked:
            messagebox.showwarning("Nothing ticked", "Tick at least one setting first.", parent=self.win)
            return False
        slug = profile_slug(name)
        target = self.app.profiles_dir / f"{slug}.yaml"
        same_file = (self.current is not None and not self.current.builtin and self.current.path is not None
                     and self.current.path.resolve() == target.resolve())
        if slug and slug not in BUILTIN_PROFILES and target.exists() and not same_file and not messagebox.askyesno(
                "Replace profile?", f"A custom profile called '{slug}' already exists. Replace it?", parent=self.win):
            return False
        try:
            path = save_profile(self.app.profiles_dir, name, self.var_desc.get(), sorted(self.ticked),
                                self.app.catalog, author=self.app.var_operator.get().strip())
        except (CatalogError, OSError) as e:
            messagebox.showerror("Could not save the profile", str(e), parent=self.win)
            return False
        self.saved = path.stem
        self._fill_choices(path.stem)
        self.lbl_info.configure(text=f"Saved: {path}")
        return True

    def delete(self) -> None:
        if not self.current or self.current.builtin or not self.current.path:
            return
        if not messagebox.askyesno("Delete profile", f"Delete the custom profile '{self.current.name}'?\n\n"
                                   f"{self.current.path}", parent=self.win):
            return
        try:
            self.current.path.unlink()
        except OSError as e:
            messagebox.showerror("Could not delete", str(e), parent=self.win)
            return
        if self.saved == self.current.name:
            self.saved = None
        self.dirty = False
        self._fill_choices("basic-safe")

    def _discard_ok(self) -> bool:
        if not self.dirty:
            return True
        return messagebox.askyesno("Unsaved changes", "Discard the changes to this profile?", parent=self.win)

    def close(self) -> None:
        if not self._discard_ok():
            return
        self.win.destroy()
        if self.on_close:
            self.on_close(self.saved)


ROLE_CHOICES = {vusers.ROLE_HELP[r]: r for r in vusers.ROLES}


class _AccountForm:
    """Username / privilege level / PTZ / password twice, for one typed-in account."""

    def __init__(self, parent, row: int, title: str, on_change, default_role: str = "viewer"):
        self.frame = ttk.LabelFrame(parent, text=f"  {title}  ", padding=6)
        self.frame.grid(row=row, column=0, sticky="ew", padx=(22, 0), pady=2)
        self.var_user = tk.StringVar()
        self.var_role = tk.StringVar(value=vusers.ROLE_HELP[default_role])
        self.var_ptz = tk.BooleanVar(value=False)
        self.var_pw1 = tk.StringVar()
        self.var_pw2 = tk.StringVar()
        f = self.frame
        ttk.Label(f, text="Username").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.ent_user = ttk.Entry(f, textvariable=self.var_user, width=22)
        self.ent_user.grid(row=0, column=1, sticky="w", pady=1)
        ttk.Label(f, text="Password").grid(row=0, column=2, sticky="w", padx=(14, 6))
        self.ent_pw1 = ttk.Entry(f, textvariable=self.var_pw1, show="*", width=20)
        self.ent_pw1.grid(row=0, column=3, sticky="w", pady=1)
        ttk.Label(f, text="Again").grid(row=0, column=4, sticky="w", padx=(10, 6))
        self.ent_pw2 = ttk.Entry(f, textvariable=self.var_pw2, show="*", width=20)
        self.ent_pw2.grid(row=0, column=5, sticky="w", pady=1)
        ttk.Label(f, text="Privilege level").grid(row=1, column=0, sticky="w", padx=(0, 6))
        self.cmb_role = ttk.Combobox(f, textvariable=self.var_role, values=list(ROLE_CHOICES), state="readonly",
                                     width=70)
        self.cmb_role.grid(row=1, column=1, columnspan=4, sticky="w", pady=1)
        self.chk_ptz = ttk.Checkbutton(f, text="+ PTZ control", variable=self.var_ptz)
        self.chk_ptz.grid(row=1, column=5, sticky="w")
        self.widgets = (self.ent_user, self.cmb_role, self.chk_ptz, self.ent_pw1, self.ent_pw2)
        for var in (self.var_user, self.var_role, self.var_ptz):
            var.trace_add("write", lambda *_: on_change())

    def enable(self, on: bool) -> None:
        for w in self.widgets:
            w.configure(state=("readonly" if w is self.cmb_role else "normal") if on else "disabled")

    @property
    def role(self) -> str:
        return ROLE_CHOICES.get(self.var_role.get(), "viewer")

    def account(self) -> NewAccount | None:
        user = self.var_user.get().strip()
        if not user:
            return None
        return NewAccount(Credential(user, self.var_pw1.get()), self.role, bool(self.var_ptz.get()))

    def problem(self) -> str | None:
        a = self.account()
        if a is None:
            return None
        prob = vusers.username_problem(a.username) or vusers.password_problem(a.credential.password, a.username)
        if prob is None and self.var_pw1.get() != self.var_pw2.get():
            prob = "the two passwords are different"
        return f"{a.username}: {prob}" if prob else None

    def clear_passwords(self) -> None:
        self.var_pw1.set("")
        self.var_pw2.set("")


class AccountDialog:
    """Create up to two separate accounts (each with a chosen privilege level) on the ticked cameras, and
    optionally remove the login account afterwards. Nothing is written until the user confirms; existing
    accounts are never changed; passwords stay in memory only."""

    def __init__(self, app: "App"):
        self.app = app
        self.win = tk.Toplevel(app.root)
        self.win.title("Create user accounts")
        self.win.transient(app.root)
        self.win.minsize(900, 640)
        self.cams = list(app.audit_cams)
        self.audit = {r.camera["host"]: r for r in app.audit_results}
        self.from_list = [c for c in self.cams if c.new_accounts]
        self.ticked: set[str] = {c.host for c in self.cams if self._ok(c)}

        f = ttk.Frame(self.win, padding=12)
        f.pack(fill="both", expand=True)
        f.columnconfigure(0, weight=1)
        f.rowconfigure(3, weight=1)
        ttk.Label(f, text="Create separate accounts with only the rights they need (for example a Viewer account for "
                  "the VMS and an Administrator account for maintenance), so the original administrator account is "
                  "not used day to day (hardening guide p.16). Accounts that already exist are never changed. "
                  "Passwords are not saved anywhere.", wraplength=870, justify="left").grid(row=0, column=0, sticky="w")

        src = ttk.LabelFrame(f, text="  Accounts to create  ", padding=8)
        src.grid(row=1, column=0, sticky="ew", pady=8)
        src.columnconfigure(0, weight=1)
        self.var_mode = tk.StringVar(value="list" if self.from_list else "typed")
        rb_list = ttk.Radiobutton(src, value="list", variable=self.var_mode, command=self.refresh,
                                  text=f"Use the accounts in the camera list (new_username/new_role/new_password and "
                                       f"new_username2/new_role2/new_password2): {len(self.from_list)} camera(s)")
        rb_list.grid(row=0, column=0, sticky="w")
        if not self.from_list:
            rb_list.configure(state="disabled", text="Use the accounts in the camera list (none: fill in the "
                                                     "new_username / new_username2 columns)")
        ttk.Radiobutton(src, value="typed", variable=self.var_mode, command=self.refresh,
                        text="Create these accounts on the ticked cameras (same password on every camera):"
                        ).grid(row=1, column=0, sticky="w", pady=(4, 2))
        self.form1 = _AccountForm(src, 2, "Account 1", self.refresh, "viewer")
        self.var_second = tk.BooleanVar(value=False)
        self.chk_second = ttk.Checkbutton(src, text="Also create a second account", variable=self.var_second,
                                          command=self.refresh)
        self.chk_second.grid(row=3, column=0, sticky="w", padx=(22, 0), pady=(4, 0))
        self.form2 = _AccountForm(src, 4, "Account 2", self.refresh, "admin")

        self.var_remove = tk.BooleanVar(value=False)
        rm = ttk.Frame(f)
        rm.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        logins = sorted({c.credential.username for c in self.cams}) or ["root"]
        ttk.Checkbutton(rm, variable=self.var_remove, command=self.refresh,
                        text=f"Then remove the account the tool logs in with ({', '.join(logins[:3])})"
                        ).grid(row=0, column=0, sticky="w")
        ttk.Label(rm, text="Needs one of the new accounts to be an Administrator. That account is checked first and "
                  "is used to do the removal, so you cannot be locked out. If a camera does not allow it (some "
                  "AXIS OS versions never let root be removed) the account is left in place. Afterwards, put the "
                  "new Administrator in the camera list's username/password columns.",
                  style="Muted.TLabel", wraplength=850, justify="left").grid(row=1, column=0, sticky="w", padx=(22, 0))

        tf = ttk.Frame(f)
        tf.grid(row=3, column=0, sticky="nsew")
        tf.columnconfigure(0, weight=1)
        tf.rowconfigure(0, weight=1)
        cols = ("tick", "camera", "ip", "existing", "create")
        heads = ("", "Camera", "IP address", "Accounts on the camera now", "Will do")
        widths = (30, 160, 110, 240, 300)
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="none", height=7)
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="center" if c == "tick" else "w", stretch=c in ("existing", "create"))
        self.tree.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.tag_configure("off", foreground="#888888")
        self.tree.bind("<Button-1>", self._click)
        self.lbl_info = ttk.Label(f, text="", style="Warn.TLabel", wraplength=870, justify="left")
        self.lbl_info.grid(row=4, column=0, sticky="w", pady=(6, 0))

        bf = ttk.Frame(f)
        bf.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        self.btn_create = ttk.Button(bf, text="Create", style="Big.TButton", command=self.create)
        self.btn_create.pack(side="right")
        ttk.Button(bf, text="Cancel", command=self.win.destroy).pack(side="right", padx=(0, 8))
        self.refresh()
        try:
            self.win.grab_set()
        except tk.TclError:
            pass

    def _ok(self, cam: Camera) -> bool:
        r = self.audit.get(cam.host)
        return r is not None and r.status == "OK"

    def _typed_accounts(self) -> list[NewAccount]:
        forms = [self.form1] + ([self.form2] if self.var_second.get() else [])
        return [a for a in (fm.account() for fm in forms) if a is not None]

    def _planned(self, cam: Camera) -> list[NewAccount]:
        if self.var_mode.get() == "list":
            return list(cam.new_accounts)
        return self._typed_accounts()

    def refresh(self) -> None:
        typed = self.var_mode.get() == "typed"
        self.form1.enable(typed)
        self.chk_second.configure(state="normal" if typed else "disabled")
        self.form2.enable(typed and self.var_second.get())
        remove = self.var_remove.get()
        self.tree.delete(*self.tree.get_children())
        for c in self.cams:
            r = self.audit.get(c.host)
            found = acc.existing_accounts(r) if r is not None and r.status == "OK" else {}
            if r is None or r.status != "OK":
                existing = STATUS_LABEL.get(r.status, r.status) if r else "not checked"
            else:
                existing = ", ".join(f"{u} ({role})" for u, role in found.items()) or "(could not read)"
            planned = self._planned(c)
            if not self._ok(c):
                create = "(camera not available)"
            elif not planned:
                create = "(nothing)" if not typed else "(type a username above)"
            else:
                parts = [f"{a.username}: already exists, left unchanged" if a.username in found else
                         f"create {a.username} as {vusers.role_label(a.role, a.ptz)}" for a in planned]
                if remove:
                    parts.append(f"then remove {c.credential.username}" if any(a.role == "admin" for a in planned)
                                 else f"keep {c.credential.username} (no new Administrator)")
                create = "; ".join(parts)
            on = c.host in self.ticked and self._ok(c)
            self.tree.insert("", "end", iid=c.host, values=(TICK if on else UNTICK, c.name or c.host, c.address,
                                                            existing, create), tags=() if on else ("off",))
        n = len(self._targets())
        self.btn_create.configure(text=f"Create on {n} camera(s)", state="normal" if n else "disabled")
        notes = []
        if typed and any(fm.role == "admin" for fm in ([self.form1] + ([self.form2] if self.var_second.get() else []))):
            notes.append("Administrator accounts have full control: give them only to people who need it.")
        if remove and not any(a.role == "admin" for c in self._targets() for a in self._planned(c)):
            notes.append("To remove the login account, one of the new accounts must be an Administrator.")
        self.lbl_info.configure(text=" ".join(notes))

    def _targets(self) -> list[Camera]:
        return [c for c in self.cams if c.host in self.ticked and self._ok(c) and self._planned(c)]

    def _click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        cam = next(c for c in self.cams if c.host == iid)
        if not self._ok(cam):
            return
        (self.ticked.discard if iid in self.ticked else self.ticked.add)(iid)
        self.refresh()

    def _ask_new_password(self, username: str) -> str | None:
        while True:
            a = simpledialog.askstring("New account password", f"The camera list has no password for the new "
                                       f"account '{username}'.\nType a password for '{username}':", show="*",
                                       parent=self.win)
            if a is None:
                return None
            b = simpledialog.askstring("New account password", f"Type the password for '{username}' again:",
                                       show="*", parent=self.win)
            if b is None:
                return None
            if a == b:
                return a
            messagebox.showwarning("Passwords differ", "The two passwords were different. Try again.",
                                   parent=self.win)

    def create(self) -> None:
        import dataclasses as _dc
        targets = self._targets()
        if not targets:
            return
        remove = bool(self.var_remove.get())
        if self.var_mode.get() == "typed":
            forms = [self.form1] + ([self.form2] if self.var_second.get() else [])
            prob = next((p for p in (fm.problem() for fm in forms) if p), None)
            accounts = self._typed_accounts()
            if prob is None and self.var_second.get() and len(accounts) < 2:
                prob = "type a username for the second account, or untick \"Also create a second account\""
            if prob:
                messagebox.showerror("Check the accounts", prob[0].upper() + prob[1:] + ".", parent=self.win)
                return
            todo = acc.with_accounts(targets, accounts)
        else:
            # copies, so typed-in passwords for blank cells do not linger on the loaded camera list
            todo = [_dc.replace(c, new_accounts=[NewAccount(a.credential, a.role, a.ptz) for a in c.new_accounts])
                    for c in targets]
            if not acc.fill_passwords(todo, self._ask_new_password):
                return
        problems = acc.account_problems(todo, remove)
        if problems:
            messagebox.showerror("Cannot create these accounts", "\n".join(problems[:10]), parent=self.win)
            return
        lines = sorted({f"  {a.username} as {vusers.role_label(a.role, a.ptz)}" for c in todo for a in c.new_accounts})
        msg = f"Create the account(s) below on {len(todo)} camera(s)?\n\n" + "\n".join(lines)
        msg += ("\n\nEach account is checked afterwards (it is listed with the right level and can log in). "
                "\"Undo last changes\" removes them again.")
        if remove:
            logins = ", ".join(sorted({c.credential.username for c in todo}))
            msg += (f"\n\nTHEN REMOVE THE LOGIN ACCOUNT ({logins}) on each camera, using the new Administrator "
                    "account (only once it has been checked). After that the tool, and anyone else, must log in "
                    "with the new Administrator account: update the camera list's username and password.")
        shared = acc.shared_new_passwords(todo) if self.var_mode.get() == "list" else []
        if shared:
            msg += "\n\nNote: some cameras get the same password (the guide recommends unique passwords, p.31)."
        if self.app.factory is not None:
            msg += "\n\n(Demo: only the recorded demo cameras change. No real camera is touched.)"
        if not messagebox.askyesno("Create accounts", msg, icon="warning", parent=self.win):
            return
        self.form1.clear_passwords()
        self.form2.clear_passwords()
        self.win.destroy()
        self.app.start_accounts(todo, remove_login=remove)


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
