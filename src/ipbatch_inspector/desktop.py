from __future__ import annotations

import json
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Callable

from .ai import infer_ai_policy, test_ai_entrances
from .iptools import extract_ips
from .providers import detect_exit_ips, scan_many
from .saved import list_redacted, load as load_saved, save as save_subscription
from .service import inspect_subscription


class InspectorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("IPBatchInspector 4")
        self.geometry("1040x720")
        self.minsize(820, 560)
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ipbatch-ui")
        self.status = tk.StringVar(value="Ready — subscription nodes are never connected")
        self.allow_private = tk.BooleanVar(value=False)
        self.resolve_only = tk.BooleanVar(value=False)
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _build(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("vista" if self.tk.call("tk", "windowingsystem") == "win32" else "clam")
        except tk.TclError:
            pass
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)
        ttk.Label(container, text="IPBatchInspector", font=("TkDefaultFont", 18, "bold")).pack(anchor="w")
        ttk.Label(container, text="Evidence-first IP intelligence · system-route checks · parse-only subscriptions").pack(anchor="w", pady=(0, 10))
        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True)
        self.ip_tab = ttk.Frame(notebook, padding=10)
        self.subscription_tab = ttk.Frame(notebook, padding=10)
        self.device_tab = ttk.Frame(notebook, padding=10)
        self.saved_tab = ttk.Frame(notebook, padding=10)
        notebook.add(self.ip_tab, text="Batch IP")
        notebook.add(self.subscription_tab, text="Subscription")
        notebook.add(self.device_tab, text="Exit & AI")
        notebook.add(self.saved_tab, text="Saved URLs")
        self._ip_ui()
        self._subscription_ui()
        self._device_ui()
        self._saved_ui()
        ttk.Separator(container).pack(fill="x", pady=(10, 4))
        ttk.Label(container, textvariable=self.status).pack(anchor="w")

    @staticmethod
    def _output(parent: ttk.Frame) -> tk.Text:
        text = tk.Text(parent, wrap="none", font=("TkFixedFont", 10), relief="solid", borderwidth=1)
        text.tag_configure("error", foreground="#b42318")
        return text

    def _ip_ui(self) -> None:
        ttk.Label(self.ip_tab, text="IPv4 / IPv6 / CIDR / mixed text (max 500 unique IPs)").pack(anchor="w")
        self.ip_input = tk.Text(self.ip_tab, height=6, font=("TkFixedFont", 10))
        self.ip_input.pack(fill="x", pady=6)
        self.ip_input.insert("1.0", "1.1.1.1\n8.8.8.8")
        ttk.Button(self.ip_tab, text="Run intelligence scan", command=self._run_ips).pack(anchor="w")
        self.ip_output = self._output(self.ip_tab)
        self.ip_output.pack(fill="both", expand=True, pady=(8, 0))

    def _subscription_ui(self) -> None:
        ttk.Label(self.subscription_tab, text="Subscription URL (public HTTPS; local HTTP requires explicit opt-in)").pack(anchor="w")
        self.subscription_url = ttk.Entry(self.subscription_tab)
        self.subscription_url.pack(fill="x", pady=6)
        controls = ttk.Frame(self.subscription_tab)
        controls.pack(fill="x")
        ttk.Checkbutton(controls, text="Allow local/private subscription retrieval", variable=self.allow_private).pack(side="left")
        ttk.Checkbutton(controls, text="DNS only, skip public intelligence", variable=self.resolve_only).pack(side="left", padx=16)
        ttk.Button(controls, text="Inspect without connecting nodes", command=self._run_subscription).pack(side="right")
        ttk.Button(controls, text="Save URL securely", command=self._save_current).pack(side="right", padx=8)
        ttk.Label(self.subscription_tab, text="Raw content is held only in memory; results redact credentials. Node ports remain metadata.", foreground="#7a3e00").pack(anchor="w", pady=6)
        self.subscription_output = self._output(self.subscription_tab)
        self.subscription_output.pack(fill="both", expand=True)

    def _device_ui(self) -> None:
        controls = ttk.Frame(self.device_tab)
        controls.pack(fill="x")
        ttk.Button(controls, text="Detect current exit IP", command=lambda: self._background("Detecting exit IP…", detect_exit_ips, self.device_output)).pack(side="left")
        ttk.Button(controls, text="Test AI public entrances", command=lambda: self._background("Testing AI entrances…", test_ai_entrances, self.device_output)).pack(side="left", padx=8)
        ttk.Label(self.device_tab, text="Uses this process's current system route. Sends no account, cookie, API key or prompt.").pack(anchor="w", pady=8)
        self.device_output = self._output(self.device_tab)
        self.device_output.pack(fill="both", expand=True)

    def _saved_ui(self) -> None:
        controls = ttk.Frame(self.saved_tab)
        controls.pack(fill="x")
        ttk.Button(controls, text="Refresh", command=self._refresh_saved).pack(side="left")
        ttk.Button(controls, text="Load selected into Subscription tab", command=self._load_selected).pack(side="left", padx=8)
        self.saved_list = tk.Listbox(self.saved_tab, font=("TkFixedFont", 10))
        self.saved_list.pack(fill="both", expand=True, pady=8)
        ttk.Label(self.saved_tab, text="Only label, scheme and hostname are shown. The complete URL is read from the OS credential store.").pack(anchor="w")
        self._refresh_saved()

    def _run_ips(self) -> None:
        ips, warnings = extract_ips([self.ip_input.get("1.0", "end")])
        if not ips:
            messagebox.showerror("No input", "No valid IP address was found.")
            return

        def work() -> dict[str, Any]:
            results = scan_many(ips)
            for item in results:
                item.ai_policy = infer_ai_policy(item.country_code, proxy=item.proxy, vpn=item.vpn, tor=item.tor, datacenter=item.datacenter, risk_scores=item.risk_scores)
            return {"warnings": warnings, "results": [item.as_dict() for item in results]}

        self._background(f"Scanning {len(ips)} IPs…", work, self.ip_output)

    def _run_subscription(self) -> None:
        url = self.subscription_url.get().strip()
        if not url:
            messagebox.showerror("Missing URL", "Enter a subscription URL.")
            return
        self._background(
            "Downloading and parsing subscription…",
            lambda: inspect_subscription(url, allow_private=self.allow_private.get(), resolve_only=self.resolve_only.get()),
            self.subscription_output,
        )

    def _save_current(self) -> None:
        url = self.subscription_url.get().strip()
        if not url:
            messagebox.showerror("Missing URL", "Enter a subscription URL first.")
            return
        name = simpledialog.askstring("Save subscription", "Display name (the token/path will not appear in the list):", parent=self)
        if not name:
            return
        try:
            save_subscription(name, url)
            self._refresh_saved()
            self.status.set(f"Saved '{name}' in the OS credential store")
        except Exception as exc:
            messagebox.showerror("Secure storage unavailable", str(exc))

    def _refresh_saved(self) -> None:
        self.saved_list.delete(0, "end")
        try:
            rows = list_redacted()
        except Exception as exc:
            self.saved_list.insert("end", f"Secure storage unavailable: {exc}")
            return
        for row in rows:
            self.saved_list.insert("end", f"{row['name']}  ·  {row['scheme']}://{row['host']}")

    def _load_selected(self) -> None:
        selection = self.saved_list.curselection()
        if not selection:
            return
        try:
            row = list_redacted()[selection[0]]
            url = load_saved(row["name"])
            self.subscription_url.delete(0, "end")
            self.subscription_url.insert(0, url)
            self.status.set(f"Loaded '{row['name']}'")
        except Exception as exc:
            messagebox.showerror("Unable to load", str(exc))

    def _background(self, label: str, call: Callable[[], Any], output: tk.Text) -> None:
        self.status.set(label)
        output.delete("1.0", "end")
        output.insert("end", label)
        future = self.pool.submit(call)

        def poll() -> None:
            if not future.done():
                self.after(100, poll)
                return
            try:
                value = future.result()
                rendered = json.dumps(value, ensure_ascii=False, indent=2, default=str)
                output.delete("1.0", "end")
                output.insert("end", rendered)
                self.status.set("Completed")
            except Exception as exc:
                output.delete("1.0", "end")
                output.insert("end", f"Error: {exc}", "error")
                self.status.set("Failed — see result panel")

        self.after(100, poll)

    def _close(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.destroy()


def main() -> None:
    InspectorApp().mainloop()


if __name__ == "__main__":
    main()
