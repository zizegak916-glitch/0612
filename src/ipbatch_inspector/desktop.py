from __future__ import annotations

import json
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Callable

from .ai import infer_ai_policy, test_ai_entrances
from .detail import detailed_investigation
from .iptools import extract_ips
from .providers import detect_exit_ips, scan_many
from .saved import list_redacted, load as load_saved, save as save_subscription
from .service import inspect_subscription
from .realtest import real_subscription_test


class InspectorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("IPBatchInspector 5")
        self.geometry("1040x720")
        self.minsize(820, 560)
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ipbatch-ui")
        self.status = tk.StringVar(value="Ready — read-only inspection is default; real VPN testing requires explicit confirmation")
        self.allow_private = tk.BooleanVar(value=False)
        self.resolve_only = tk.BooleanVar(value=False)
        self.fresh = tk.BooleanVar(value=False)
        self.real_open_browser = tk.BooleanVar(value=False)
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
        ttk.Label(container, text="Evidence-first IP intelligence · single-IP OSINT · isolated real system-VPN tests").pack(anchor="w", pady=(0, 10))
        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True)
        self.ip_tab = ttk.Frame(notebook, padding=10)
        self.subscription_tab = ttk.Frame(notebook, padding=10)
        self.device_tab = ttk.Frame(notebook, padding=10)
        self.detail_tab = ttk.Frame(notebook, padding=10)
        self.realtest_tab = ttk.Frame(notebook, padding=10)
        self.saved_tab = ttk.Frame(notebook, padding=10)
        notebook.add(self.ip_tab, text="Batch IP")
        notebook.add(self.detail_tab, text="Single-IP Detail")
        notebook.add(self.subscription_tab, text="Subscription")
        notebook.add(self.realtest_tab, text="Real VPN Test")
        notebook.add(self.device_tab, text="Exit & AI")
        notebook.add(self.saved_tab, text="Saved URLs")
        self._ip_ui()
        self._detail_ui()
        self._subscription_ui()
        self._realtest_ui()
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
        ip_controls = ttk.Frame(self.ip_tab)
        ip_controls.pack(fill="x")
        ttk.Button(ip_controls, text="Run intelligence scan", command=self._run_ips).pack(side="left")
        ttk.Checkbutton(ip_controls, text="Force refresh (bypass cache)", variable=self.fresh).pack(side="left", padx=16)
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
        ttk.Checkbutton(controls, text="Force refresh", variable=self.fresh).pack(side="left")
        ttk.Button(controls, text="Inspect without connecting nodes", command=self._run_subscription).pack(side="right")
        ttk.Button(controls, text="Save URL securely", command=self._save_current).pack(side="right", padx=8)
        ttk.Label(self.subscription_tab, text="Raw content is held only in memory; results redact credentials. Node ports remain metadata.", foreground="#7a3e00").pack(anchor="w", pady=6)
        self.subscription_output = self._output(self.subscription_tab)
        self.subscription_output.pack(fill="both", expand=True)

    def _detail_ui(self) -> None:
        ttk.Label(self.detail_tab, text="Exactly one public IPv4/IPv6 · registration, routing, passive security, PTR and current TLS certificate").pack(anchor="w")
        row = ttk.Frame(self.detail_tab)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text="Public IP").pack(side="left")
        self.detail_ip = ttk.Entry(row, width=42)
        self.detail_ip.pack(side="left", padx=8)
        self.detail_ip.insert(0, "1.1.1.1")
        ttk.Label(row, text="TLS port(s)").pack(side="left")
        self.detail_ports = ttk.Entry(row, width=18)
        self.detail_ports.pack(side="left", padx=8)
        self.detail_ports.insert(0, "443")
        ttk.Button(row, text="Run detailed investigation", command=self._run_detail).pack(side="right")
        ttk.Label(
            self.detail_tab,
            text="Passive databases are labelled separately. Only the listed TLS ports are contacted; no port scan is performed.",
            foreground="#7a3e00",
        ).pack(anchor="w", pady=(0, 6))
        self.detail_output = self._output(self.detail_tab)
        self.detail_output.pack(fill="both", expand=True)

    def _realtest_ui(self) -> None:
        ttk.Label(self.realtest_tab, text="Real subscription test through an already-running Clash/Mihomo/Clash Mate system VPN").pack(anchor="w")
        form = ttk.Frame(self.realtest_tab)
        form.pack(fill="x", pady=6)
        for column in (1, 3):
            form.columnconfigure(column, weight=1)
        ttk.Label(form, text="Subscription URL").grid(row=0, column=0, sticky="w", padx=(0, 6), pady=3)
        self.real_subscription_url = ttk.Entry(form)
        self.real_subscription_url.grid(row=0, column=1, columnspan=3, sticky="ew", pady=3)
        ttk.Label(form, text="Local controller").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=3)
        self.real_controller = ttk.Entry(form)
        self.real_controller.grid(row=1, column=1, sticky="ew", pady=3)
        self.real_controller.insert(0, "http://127.0.0.1:9090")
        ttk.Label(form, text="Secret (not saved)").grid(row=1, column=2, sticky="w", padx=6, pady=3)
        self.real_secret = ttk.Entry(form, show="•")
        self.real_secret.grid(row=1, column=3, sticky="ew", pady=3)
        ttk.Label(form, text="Selector group").grid(row=2, column=0, sticky="w", padx=(0, 6), pady=3)
        self.real_group = ttk.Entry(form)
        self.real_group.grid(row=2, column=1, sticky="ew", pady=3)
        ttk.Label(form, text="Exact node (blank=matching nodes)").grid(row=2, column=2, sticky="w", padx=6, pady=3)
        self.real_node = ttk.Entry(form)
        self.real_node.grid(row=2, column=3, sticky="ew", pady=3)
        ttk.Label(form, text="AI presets").grid(row=3, column=0, sticky="w", padx=(0, 6), pady=3)
        self.real_targets = ttk.Entry(form)
        self.real_targets.grid(row=3, column=1, sticky="ew", pady=3)
        self.real_targets.insert(0, "all")
        ttk.Label(form, text="Custom HTTPS URL/domain").grid(row=3, column=2, sticky="w", padx=6, pady=3)
        self.real_custom = ttk.Entry(form)
        self.real_custom.grid(row=3, column=3, sticky="ew", pady=3)
        actions = ttk.Frame(self.realtest_tab)
        actions.pack(fill="x")
        ttk.Checkbutton(actions, text="Open conversation pages and leave the one tested node selected", variable=self.real_open_browser).pack(side="left")
        ttk.Button(actions, text="Start explicit real test", command=self._run_realtest).pack(side="right")
        ttk.Label(
            self.realtest_tab,
            text="Requires TUN/VPN enabled. It changes the selected policy group, sends no login cookie or prompt, and restores the original node unless browser opening is requested.",
            foreground="#9b1c1c",
            wraplength=980,
        ).pack(anchor="w", pady=6)
        self.realtest_output = self._output(self.realtest_tab)
        self.realtest_output.pack(fill="both", expand=True)

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
        fresh = self.fresh.get()
        if not ips:
            messagebox.showerror("No input", "No valid IP address was found.")
            return

        def work() -> dict[str, Any]:
            results = scan_many(ips, fresh=fresh)
            for item in results:
                item.ai_policy = infer_ai_policy(item.country_code, proxy=item.proxy, vpn=item.vpn, tor=item.tor, datacenter=item.datacenter, risk_scores=item.risk_scores)
            return {"warnings": warnings, "results": [item.as_dict() for item in results]}

        self._background(f"Scanning {len(ips)} IPs…", work, self.ip_output)

    def _run_subscription(self) -> None:
        url = self.subscription_url.get().strip()
        if not url:
            messagebox.showerror("Missing URL", "Enter a subscription URL.")
            return
        allow_private = self.allow_private.get()
        resolve_only = self.resolve_only.get()
        fresh = self.fresh.get()
        self._background(
            "Downloading and parsing subscription…",
            lambda: inspect_subscription(
                url,
                allow_private=allow_private,
                resolve_only=resolve_only,
                fresh=fresh,
            ),
            self.subscription_output,
        )

    def _run_detail(self) -> None:
        value = self.detail_ip.get().strip()
        fresh = self.fresh.get()
        try:
            ports = tuple(int(item.strip()) for item in self.detail_ports.get().split(",") if item.strip())
        except ValueError:
            messagebox.showerror("Invalid port", "TLS ports must be comma-separated integers.")
            return
        self._background(
            "Running single-IP detailed investigation…",
            lambda: detailed_investigation(value, tls_ports=ports or (443,), fresh=fresh),
            self.detail_output,
        )

    def _run_realtest(self) -> None:
        url = self.real_subscription_url.get().strip()
        if not url:
            messagebox.showerror("Missing URL", "Enter a subscription URL.")
            return
        node = self.real_node.get().strip()
        controller = self.real_controller.get().strip()
        controller_secret = self.real_secret.get()
        group = self.real_group.get().strip() or None
        presets = tuple(item.strip() for item in self.real_targets.get().split(",") if item.strip())
        custom = tuple(item.strip() for item in self.real_custom.get().split(",") if item.strip())
        open_browser = self.real_open_browser.get()
        if open_browser and not node:
            messagebox.showerror("Select one node", "Browser mode requires one exact node name so the route is not left on an arbitrary node.")
            return
        if not messagebox.askyesno(
            "Real system-VPN test",
            "This will switch the selected node in your local VPN controller and make real requests to the listed sites. Continue?",
        ):
            return
        self._background(
            "Switching real VPN node and testing conversation URLs…",
            lambda: real_subscription_test(
                url,
                controller_url=controller,
                controller_secret=controller_secret,
                group=group,
                nodes=(node,) if node else (),
                presets=presets,
                custom_targets=custom,
                max_nodes=20,
                open_browser=open_browser,
            ),
            self.realtest_output,
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
