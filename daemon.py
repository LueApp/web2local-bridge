#!/usr/bin/env python3
"""web2local daemon — bridges websites to local command execution safely."""

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Config ───────────────────────────────────────────────────────────────────

CONFIG_DIR    = os.path.expanduser("~/.config/web2local")
CONFIG_PATH   = os.path.join(CONFIG_DIR, "config.json")
LOG_PATH      = os.path.join(CONFIG_DIR, "audit.log")
PROC_DIR      = os.path.join(CONFIG_DIR, "processes")  # per-PID log files
PROC_INDEX    = os.path.join(CONFIG_DIR, "processes.json")  # PID → metadata

DEFAULT_CONFIG = {"port": 7878, "whitelist": [], "graylist": []}

_config      = DEFAULT_CONFIG.copy()
_config_lock = threading.Lock()


def _load_config():
    global _config
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            data = json.load(f)
        with _config_lock:
            _config = {**DEFAULT_CONFIG, **data}
    else:
        with _config_lock:
            _config = DEFAULT_CONFIG.copy()


def _save_config(cfg: dict):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def _get_config() -> dict:
    with _config_lock:
        return _config.copy()


def _update_config(new: dict):
    global _config
    with _config_lock:
        _config = new


# ── Audit log ────────────────────────────────────────────────────────────────

def _audit(action: str, origin: str, command: list, outcome: str):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    ts   = datetime.datetime.now().isoformat(timespec="seconds")
    line = f"{ts} | {action:<10} | {origin} | {json.dumps(command)} | {outcome}\n"
    with open(LOG_PATH, "a") as f:
        f.write(line)


# ── Process registry ─────────────────────────────────────────────────────────
# Long-running children are spawned non-blocking. Each is registered with its
# PID, the start time we observed, the command, the origin that spawned it,
# and a log file path. Liveness is checked on every /ps call.

_proc_lock = threading.Lock()


def _proc_starttime(pid: int):
    """Return the kernel's recorded start_time for a PID, or None if it is gone.
    Used to detect PID reuse — a fresh process at the same PID will have a
    different start_time, so we treat it as not ours."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        # /proc/<pid>/stat: pid (comm) state ppid ... — comm may contain spaces
        # and parens, so split from the last ')' to safely skip it.
        rest = data[data.rindex(")") + 2:].split()
        return rest[19]  # field 22 (1-indexed) is starttime
    except (FileNotFoundError, ProcessLookupError, ValueError, IndexError):
        return None


def _proc_alive(pid: int, expected_starttime: str) -> bool:
    """True only if pid exists AND start_time matches what we recorded."""
    actual = _proc_starttime(pid)
    return actual is not None and actual == expected_starttime


def _proc_load() -> list:
    if not os.path.exists(PROC_INDEX):
        return []
    try:
        with open(PROC_INDEX) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _proc_save(entries: list):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(PROC_INDEX, "w") as f:
        json.dump(entries, f, indent=2)


def _proc_list_live() -> list:
    """Return registry filtered to processes that are still alive.
    Also prunes dead entries from the on-disk index."""
    with _proc_lock:
        entries = _proc_load()
        live    = [e for e in entries if _proc_alive(e["pid"], e["starttime"])]
        if len(live) != len(entries):
            _proc_save(live)
        return live


def _proc_register(pid: int, starttime: str, cmd_list: list,
                   origin: str, log_path: str):
    entry = {
        "pid":        pid,
        "starttime":  starttime,
        "command":    cmd_list,
        "origin":     origin,
        "log_path":   log_path,
        "started_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }
    with _proc_lock:
        entries = [e for e in _proc_load() if e["pid"] != pid]
        entries.append(entry)
        _proc_save(entries)
    return entry


def _proc_remove(pid: int):
    with _proc_lock:
        entries = [e for e in _proc_load() if e["pid"] != pid]
        _proc_save(entries)


def _proc_spawn(cmd_list: list, origin: str):
    """Start a long-running process; return its registry entry."""
    os.makedirs(PROC_DIR, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(PROC_DIR, f"{ts}-{cmd_list[0].split('/')[-1]}.log")

    # Open as line-buffered so /logs sees output promptly.
    log_fh = open(log_path, "wb")

    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # own session/process group, survives daemon
            close_fds=True,
        )
    except (FileNotFoundError, OSError) as e:
        log_fh.close()
        raise

    starttime = _proc_starttime(proc.pid) or ""
    entry     = _proc_register(proc.pid, starttime, cmd_list, origin, log_path)
    return entry


def _proc_stop(pid: int) -> dict:
    """Stop a registered process. SIGTERM, wait 3s, then SIGKILL its group."""
    entries = _proc_list_live()
    entry   = next((e for e in entries if e["pid"] == pid), None)
    if not entry:
        return {"status": "not_found"}

    # Negative PID = whole process group (set up by start_new_session=True).
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        _proc_remove(pid)
        return {"status": "already_gone"}

    # Wait up to 3 s for graceful shutdown.
    for _ in range(30):
        if not _proc_alive(pid, entry["starttime"]):
            _proc_remove(pid)
            return {"status": "stopped", "signal": "SIGTERM"}
        threading.Event().wait(0.1)

    # Still alive — escalate.
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    _proc_remove(pid)
    return {"status": "stopped", "signal": "SIGKILL"}


def _proc_tail(log_path: str, lines: int = 200) -> str:
    """Return the last N lines of a process log, or '' if missing."""
    if not log_path or not os.path.exists(log_path):
        return ""
    # Simple tail — fine for small log sizes; we cap reads anyway.
    with open(log_path, "rb") as f:
        try:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, 64 * 1024)
            f.seek(size - chunk)
            data = f.read().decode("utf-8", errors="replace")
        except OSError:
            data = ""
    return "\n".join(data.splitlines()[-lines:])


# ── Graylist confirmation dialog ─────────────────────────────────────────────
# Main thread runs the GUI loop; HTTP worker threads enqueue requests and
# block on a threading.Event until the user responds.

_dialog_queue  = queue.Queue()
_dialog_active = False


def _run_gui_loop():
    """Blocking GUI loop — call from main thread only."""
    try:
        import tkinter as tk
        _run_tk_loop(tk)
    except ImportError:
        _run_terminal_loop()


def _run_tk_loop(tk):
    global _dialog_active

    root = tk.Tk()
    root.withdraw()

    def _check():
        global _dialog_active
        if not _dialog_active:
            try:
                item = _dialog_queue.get_nowait()
                _dialog_active = True
                _show_tk_dialog(tk, root, item)
            except queue.Empty:
                pass
        root.after(100, _check)

    root.after(100, _check)
    root.mainloop()


def _show_tk_dialog(tk, root, item):
    global _dialog_active
    origin, cmd_list, event, result = item
    alive = [True]

    dlg = tk.Toplevel(root)
    dlg.title("web2local — Command Approval")
    dlg.resizable(True, True)
    dlg.attributes("-topmost", True)
    dlg.minsize(560, 400)

    # Header bar
    hdr = tk.Frame(dlg, bg="#1a1a2e", pady=14)
    hdr.pack(fill="x")
    tk.Label(hdr, text="⚠  Command Approval Required",
             bg="#1a1a2e", fg="white", font=("Arial", 13, "bold")).pack()

    body = tk.Frame(dlg, padx=22, pady=12)
    body.pack(fill="both", expand=True)

    tk.Label(body, text="Requesting website:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x")
    tk.Label(body, text=origin, fg="#d4860a", font=("Courier", 10), anchor="w").pack(fill="x", pady=(0, 12))

    tk.Label(body, text="Command to execute:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x")

    frm = tk.Frame(body, relief="sunken", bd=1)
    frm.pack(fill="both", expand=True, pady=(4, 0))

    txt  = tk.Text(frm, font=("Courier", 10), height=9, wrap="none",
                   bg="#1e1e1e", fg="#d4d4d4")
    sb_y = tk.Scrollbar(frm, orient="vertical",   command=txt.yview)
    sb_x = tk.Scrollbar(frm, orient="horizontal", command=txt.xview)
    txt.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)

    # Display command as shell-like string (quoted where needed)
    display = " ".join(
        f'"{a}"' if (" " in a or not a) else a
        for a in cmd_list
    )
    txt.insert("end", display)
    txt.config(state="disabled")

    sb_y.pack(side="right",  fill="y")
    sb_x.pack(side="bottom", fill="x")
    txt.pack(fill="both", expand=True)

    tk.Label(body,
             text="Read the full command carefully. Scroll right if it is long.",
             fg="#cc0000", font=("Arial", 9, "italic"), anchor="w").pack(fill="x", pady=(8, 0))

    remaining  = [120]
    timer_var  = tk.StringVar(value="Auto-deny in 120 s")
    tk.Label(body, textvariable=timer_var, fg="#888", font=("Arial", 8), anchor="w").pack(fill="x")

    def _tick():
        if not alive[0]:
            return
        remaining[0] -= 1
        if remaining[0] <= 0:
            _deny()
            return
        timer_var.set(f"Auto-deny in {remaining[0]} s")
        dlg.after(1000, _tick)

    dlg.after(1000, _tick)

    def _approve():
        global _dialog_active
        if not alive[0]:
            return
        alive[0]       = False
        result[0]      = True
        _dialog_active = False
        event.set()
        dlg.destroy()

    def _deny():
        global _dialog_active
        if not alive[0]:
            return
        alive[0]       = False
        result[0]      = False
        _dialog_active = False
        event.set()
        dlg.destroy()

    dlg.protocol("WM_DELETE_WINDOW", _deny)

    btn = tk.Frame(dlg, padx=22, pady=14)
    btn.pack(fill="x")

    tk.Button(btn, text="Deny", command=_deny,
              bg="#c0392b", fg="white", font=("Arial", 10, "bold"),
              width=12, relief="flat", pady=6).pack(side="left")
    tk.Button(btn, text="Allow Execution", command=_approve,
              bg="#27ae60", fg="white", font=("Arial", 10, "bold"),
              width=16, relief="flat", pady=6).pack(side="right")

    dlg.update_idletasks()
    sw, sh = dlg.winfo_screenwidth(), dlg.winfo_screenheight()
    w,  h  = dlg.winfo_width(),       dlg.winfo_height()
    dlg.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")


def _run_terminal_loop():
    """Fallback when tkinter is unavailable."""
    while True:
        try:
            item           = _dialog_queue.get(timeout=1)
            origin, cmd_list, event, result = item
            sep            = "=" * 60
            display        = " ".join(cmd_list)
            print(f"\n{sep}")
            print("[web2local] COMMAND APPROVAL REQUIRED")
            print(sep)
            print(f"  Site   : {origin}")
            print(f"  Command: {display}")
            print(sep)
            try:
                ans       = input("  Allow? (y/N): ").strip().lower()
                result[0] = (ans == "y")
            except (EOFError, KeyboardInterrupt):
                result[0] = False
                print("\n[auto-denied]")
            event.set()
        except queue.Empty:
            pass


def _request_approval(origin: str, cmd_list: list) -> bool:
    """Queue a graylist dialog and block until the user responds."""
    event  = threading.Event()
    result = [False]
    _dialog_queue.put((origin, cmd_list, event, result))
    event.wait(timeout=135)  # 15s longer than auto-deny
    return result[0]


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _send_json(handler, status: int, data: dict, origin: str = ""):
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type",   "application/json")
    handler.send_header("Content-Length", str(len(body)))
    if origin:
        handler.send_header("Access-Control-Allow-Origin",          origin)
        handler.send_header("Access-Control-Allow-Methods",         "GET, POST, OPTIONS")
        handler.send_header("Access-Control-Allow-Headers",         "Content-Type")
        handler.send_header("Access-Control-Allow-Private-Network", "true")
        handler.send_header("Vary", "Origin")
    handler.end_headers()
    handler.wfile.write(body)


# ── Request handler ───────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, *_):
        pass  # silence default access log

    # ── helpers ──

    def _origin(self) -> str:
        return self.headers.get("Origin", "")

    def _host_ok(self) -> bool:
        """Reject DNS-rebinding: Host must be 127.0.0.1 or localhost."""
        host = self.headers.get("Host", "").split(":")[0]
        return host in ("127.0.0.1", "localhost", "[::1]")

    def _classify(self, origin: str):
        """Return 'whitelist', 'graylist', or None."""
        norm = origin.rstrip("/")
        cfg  = _get_config()
        if norm in [o.rstrip("/") for o in cfg["whitelist"]]:
            return "whitelist"
        if norm in [o.rstrip("/") for o in cfg["graylist"]]:
            return "graylist"
        return None

    def _read_body(self) -> dict:
        n    = int(self.headers.get("Content-Length", 0))
        raw  = self.rfile.read(n) if n else b"{}"
        return json.loads(raw)

    # ── CORS preflight ──

    def do_OPTIONS(self):
        origin = self._origin()
        path   = self.path.split("?")[0]
        if not self._host_ok():
            self.send_response(403); self.end_headers(); return
        # /run requires the origin to already be in a list.
        # Config endpoints have no such restriction — that's how you add yourself.
        if path == "/run" and not self._classify(origin):
            self.send_response(403); self.end_headers(); return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",          origin)
        self.send_header("Access-Control-Allow-Methods",         "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",         "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age",               "3600")
        self.end_headers()

    # ── GET ──

    def do_GET(self):
        origin = self._origin()
        full   = self.path
        path   = full.split("?")[0]

        if path == "/status":
            # Allow any origin — reveals no sensitive data, lets sites detect daemon.
            # Host header still guards against DNS rebinding.
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}); return
            _send_json(self, 200, {"status": "running", "version": "1.0.0"}, origin)
            return

        if path == "/config":
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}); return
            _send_json(self, 200, _get_config(), origin)
            return

        if path == "/log":
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}); return
            entries = []
            if os.path.exists(LOG_PATH):
                with open(LOG_PATH) as f:
                    entries = [l.rstrip() for l in f.readlines()[-200:]]
            _send_json(self, 200, {"entries": entries}, origin)
            return

        if path == "/ps":
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}); return
            _send_json(self, 200, {"processes": _proc_list_live()}, origin)
            return

        if path == "/logs":
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}); return
            from urllib.parse import urlparse, parse_qs
            q   = parse_qs(urlparse(full).query)
            pid = int(q.get("pid", ["0"])[0] or 0)
            entry = next((e for e in _proc_load() if e["pid"] == pid), None)
            if not entry:
                _send_json(self, 404, {"error": "unknown pid"}, origin); return
            _send_json(self, 200,
                       {"pid": pid, "tail": _proc_tail(entry["log_path"], 200)},
                       origin)
            return

        self.send_response(404); self.end_headers()

    # ── POST ──

    def do_POST(self):
        origin = self._origin()
        path   = self.path.split("?")[0]

        if not self._host_ok():
            _send_json(self, 403, {"error": "host must be 127.0.0.1 or localhost"}, origin)
            _audit("BLOCKED", origin or "unknown", [], "invalid_host")
            return

        try:
            data = self._read_body()
        except (json.JSONDecodeError, ValueError):
            _send_json(self, 400, {"error": "invalid JSON"}, origin); return

        # ── Config endpoints (no origin gate — management by local user) ──

        if path == "/config/reload":
            _load_config()
            _send_json(self, 200, {"status": "reloaded"}, origin)
            return

        if path in ("/config/whitelist", "/config/graylist"):
            url = data.get("origin", "").rstrip("/")
            if not url:
                _send_json(self, 400, {"error": "missing origin"}, origin); return
            cfg  = _get_config()
            list_key  = "whitelist" if path == "/config/whitelist" else "graylist"
            other_key = "graylist"  if list_key == "whitelist"     else "whitelist"
            cfg[other_key] = [o for o in cfg[other_key] if o.rstrip("/") != url]
            if url not in [o.rstrip("/") for o in cfg[list_key]]:
                cfg[list_key].append(url)
            _update_config(cfg)
            _save_config(cfg)
            _send_json(self, 200, {"status": "added", "list": list_key, "origin": url}, origin)
            return

        if path == "/config/remove":
            url = data.get("origin", "").rstrip("/")
            cfg = _get_config()
            cfg["whitelist"] = [o for o in cfg["whitelist"] if o.rstrip("/") != url]
            cfg["graylist"]  = [o for o in cfg["graylist"]  if o.rstrip("/") != url]
            _update_config(cfg)
            _save_config(cfg)
            _send_json(self, 200, {"status": "removed"}, origin)
            return

        # ── /spawn — start a long-running process, return immediately ──

        if path == "/spawn":
            classification = self._classify(origin)
            if not classification:
                _send_json(self, 403, {"error": "origin not in whitelist or graylist"}, origin)
                _audit("BLOCKED", origin or "unknown", [], "not_in_list")
                return

            command = data.get("command", "")
            args    = data.get("args", [])
            if not command or not isinstance(command, str):
                _send_json(self, 400, {"error": "command must be a non-empty string"}, origin); return
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                _send_json(self, 400, {"error": "args must be a list of strings"}, origin); return

            cmd_list = [command] + args

            if classification == "graylist":
                approved = _request_approval(origin, ["[spawn]"] + cmd_list)
                if not approved:
                    _send_json(self, 403, {"error": "spawn denied by user"}, origin)
                    _audit("DENIED", origin, cmd_list, "spawn_denied_by_user")
                    return
                _audit("APPROVED", origin, cmd_list, "spawn_approved_by_user")
            else:
                _audit("ALLOWED", origin, cmd_list, "spawn_whitelist")

            try:
                entry = _proc_spawn(cmd_list, origin)
                _send_json(self, 200, {
                    "pid":        entry["pid"],
                    "started_at": entry["started_at"],
                    "log_path":   entry["log_path"],
                }, origin)
            except FileNotFoundError:
                _send_json(self, 400, {"error": f"command not found: {command}"}, origin)
                _audit("ERROR", origin, cmd_list, "spawn_command_not_found")
            except OSError as e:
                _send_json(self, 500, {"error": f"spawn failed: {e}"}, origin)
                _audit("ERROR", origin, cmd_list, f"spawn_oserror:{e}")
            return

        # ── /stop — terminate a registered process ──

        if path == "/stop":
            classification = self._classify(origin)
            if not classification:
                _send_json(self, 403, {"error": "origin not in whitelist or graylist"}, origin)
                return
            try:
                pid = int(data.get("pid", 0))
            except (TypeError, ValueError):
                _send_json(self, 400, {"error": "pid must be an integer"}, origin); return
            if pid <= 0:
                _send_json(self, 400, {"error": "missing or invalid pid"}, origin); return

            result = _proc_stop(pid)
            _audit("STOP", origin, [str(pid)], result.get("status", "?"))
            _send_json(self, 200, result, origin)
            return

        # ── /run ──

        if path == "/run":
            classification = self._classify(origin)
            if not classification:
                _send_json(self, 403,
                           {"error": "origin not in whitelist or graylist"}, origin)
                _audit("BLOCKED", origin or "unknown", [], "not_in_list")
                return

            command = data.get("command", "")
            args    = data.get("args", [])

            if not command or not isinstance(command, str):
                _send_json(self, 400, {"error": "command must be a non-empty string"}, origin); return
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                _send_json(self, 400, {"error": "args must be a list of strings"}, origin); return

            cmd_list = [command] + args

            if classification == "graylist":
                approved = _request_approval(origin, cmd_list)
                if not approved:
                    _send_json(self, 403, {"error": "command denied by user"}, origin)
                    _audit("DENIED", origin, cmd_list, "denied_by_user")
                    return
                _audit("APPROVED", origin, cmd_list, "approved_by_user")
            else:
                _audit("ALLOWED", origin, cmd_list, "whitelist")

            try:
                proc = subprocess.run(
                    cmd_list, capture_output=True, text=True, timeout=30
                )
                _send_json(self, 200, {
                    "stdout":    proc.stdout,
                    "stderr":    proc.stderr,
                    "exit_code": proc.returncode,
                }, origin)
            except FileNotFoundError:
                _send_json(self, 400, {"error": f"command not found: {command}"}, origin)
                _audit("ERROR", origin, cmd_list, "command_not_found")
            except subprocess.TimeoutExpired:
                _send_json(self, 408, {"error": "command timed out (30 s limit)"}, origin)
                _audit("ERROR", origin, cmd_list, "timeout")
            return

        self.send_response(404); self.end_headers()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    _load_config()
    cfg  = _get_config()
    port = cfg.get("port", 7878)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    print(f"web2local running  →  http://127.0.0.1:{port}")
    print(f"Config : {CONFIG_PATH}")
    print(f"Log    : {LOG_PATH}")
    print("Press Ctrl+C to stop.\n")

    try:
        _run_gui_loop()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        print("\nweb2local stopped.")


if __name__ == "__main__":
    main()
