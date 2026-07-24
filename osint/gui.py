"""
Tkinter GUI for the OSINT Toolkit (standard library only).

Tabs: DNS · WHOIS · Username. Network work runs on background threads; only the
main thread touches widgets (via a queue). Authorized use only.
"""

from __future__ import annotations

import queue
import threading

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

try:
    from osint import dns_recon, whois_intel, username_check
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from osint import dns_recon, whois_intel, username_check


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("OSINT Toolkit")
        self.geometry("820x640")
        self.minsize(700, 520)
        self.ui_queue: "queue.Queue" = queue.Queue()
        self.after(60, self._drain)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        nb.add(_SimpleTab(nb, self, "Domain", "DNS records",
                          lambda v: dns_recon.recon(v).as_text()), text="  DNS  ")
        nb.add(_SimpleTab(nb, self, "Domain or IP", "WHOIS lookup",
                          lambda v: whois_intel.lookup(v).as_text()), text="  WHOIS  ")
        nb.add(_SimpleTab(nb, self, "Username", "Search sites",
                          lambda v: username_check.check(v).as_text()), text="  Username  ")

        self.status = ttk.Label(self, relief="sunken", anchor="w",
                                text="Ready - authorized use only.")
        self.status.pack(fill="x", side="bottom")

    def set_status(self, msg): self.status.configure(text=msg)

    def _drain(self):
        try:
            while True:
                cb = self.ui_queue.get_nowait()
                try:
                    cb()
                except Exception:  # noqa: BLE001
                    self.set_status("A UI update failed.")
        except queue.Empty:
            pass
        self.after(60, self._drain)


class _SimpleTab(ttk.Frame):
    def __init__(self, master, app, label, action, fn):
        super().__init__(master, padding=10)
        self.app, self.fn = app, fn
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        ttk.Label(self, text=label).grid(row=0, column=0, sticky="w")
        self.value = tk.StringVar()
        ttk.Entry(self, textvariable=self.value).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        self.btn = ttk.Button(ctl, text=action, command=self.run); self.btn.pack(side="right")
        self.out = scrolledtext.ScrolledText(self, wrap="word", font=("Consolas", 10),
                                             state="disabled")
        self.out.grid(row=3, column=0, sticky="nsew", pady=(8, 0))

    def run(self):
        v = self.value.get().strip()
        if not v:
            messagebox.showinfo("No input", "Enter a value first."); return
        self.btn.configure(state="disabled")
        self.app.set_status("Working…")

        def worker():
            try:
                res = self.fn(v)
            except Exception as exc:  # noqa: BLE001
                res = f"Error: {exc}"

            def finish():
                self.out.configure(state="normal")
                self.out.delete("1.0", "end")
                self.out.insert("1.0", res)
                self.out.configure(state="disabled")
                self.btn.configure(state="normal")
                self.app.set_status("Done.")
            self.app.ui_queue.put(finish)

        threading.Thread(target=worker, daemon=True).start()


def main() -> int:
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
