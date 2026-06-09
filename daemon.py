#!/usr/bin/env python3
"""web2local daemon — bridges websites to local command execution safely."""

import copy
import hashlib
import json
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import datetime
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Config ───────────────────────────────────────────────────────────────────

CONFIG_DIR    = os.path.expanduser("~/.config/web2local")
CONFIG_PATH   = os.path.join(CONFIG_DIR, "config.json")
LOG_PATH      = os.path.join(CONFIG_DIR, "audit.log")
PROC_DIR      = os.path.join(CONFIG_DIR, "processes")   # per-PID log files
PROC_INDEX    = os.path.join(CONFIG_DIR, "processes.json")
AGENTS_DIR    = os.path.join(CONFIG_DIR, "agents")      # deployed scripts
ENVS_DIR      = os.path.join(CONFIG_DIR, "envs")        # daemon-created python envs

DEFAULT_CONFIG = {"port": 7878, "whitelist": [], "graylist": [], "python": ""}

_config      = DEFAULT_CONFIG.copy()
_config_lock = threading.Lock()


def _load_config():
    global _config
    data = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                data = {}
        except (json.JSONDecodeError, OSError):
            # A corrupt or unreadable config must never brick startup — fall
            # back to defaults (the atomic writer below makes this rare anyway).
            data = {}
    with _config_lock:
        _config = {**DEFAULT_CONFIG, **data}
        # A hand-edited config may set "python" to a non-string (e.g. 3 or a
        # list). Normalize to "" so the interpreter resolver — on the hot path
        # of every /run, /spawn, /deploy — never trips on .strip().
        if not isinstance(_config.get("python"), str):
            _config["python"] = ""


def _write_config_file(cfg: dict):
    """Atomically write config.json (temp file + fsync + os.replace). Does NOT
    lock — callers must already hold _config_lock. os.replace is atomic on the
    same filesystem, so a reader or the next startup never sees a torn file."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=CONFIG_DIR, prefix=".config.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, CONFIG_PATH)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _save_config(cfg: dict):
    with _config_lock:
        _write_config_file(cfg)


def _mutate_config(fn):
    """Atomically read-modify-write config under one lock: snapshot → apply fn →
    publish → persist. Multiple writers now exist (HTTP handler threads AND the
    setup worker thread), so a plain get→modify→update→save would let one writer
    silently clobber another's field; this makes the whole sequence indivisible."""
    global _config
    with _config_lock:
        cfg = copy.deepcopy(_config)
        fn(cfg)
        _config = cfg
        _write_config_file(cfg)


def _get_config() -> dict:
    with _config_lock:
        return copy.deepcopy(_config)


def _update_config(new: dict):
    global _config
    with _config_lock:
        _config = new


# ── Session trust ─────────────────────────────────────────────────────────────
# Origins trusted for this daemon session only — cleared on restart, never
# written to config.json. Treated identically to graylist entries.

_session_trusted: set = set()
_session_lock = threading.Lock()


def _is_session_trusted(origin: str) -> bool:
    with _session_lock:
        return origin.rstrip("/") in _session_trusted


def _add_session_trust(origin: str):
    with _session_lock:
        _session_trusted.add(origin.rstrip("/"))


# ── Dialog flood protection ───────────────────────────────────────────────────
# A hostile page can POST in a tight loop to wear the user down.
# After _FLOOD_MAX dialogs in _FLOOD_WINDOW seconds the origin is banned for
# _FLOOD_BAN seconds and all further approval requests auto-deny.

_flood_lock    = threading.Lock()
_flood_tracker: dict = {}  # origin -> {count, window_start, banned_until}
_FLOOD_WINDOW  = 60    # seconds per window
_FLOOD_MAX     = 3     # max dialogs per window before ban
_FLOOD_BAN     = 300   # ban duration in seconds


def _flood_check(origin: str) -> bool:
    """Return True if origin may show a dialog, False if rate-limited."""
    now = time.monotonic()
    with _flood_lock:
        rec = _flood_tracker.get(origin, {})
        if rec.get("banned_until", 0) > now:
            return False
        if now - rec.get("window_start", 0) > _FLOOD_WINDOW:
            rec = {"count": 0, "window_start": now, "banned_until": 0.0}
        rec["count"] = rec.get("count", 0) + 1
        if rec["count"] > _FLOOD_MAX:
            rec["banned_until"] = now + _FLOOD_BAN
            _flood_tracker[origin] = rec
            return False
        _flood_tracker[origin] = rec
        return True


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


def _proc_stat(pid: int):
    """Return (state, starttime) from /proc/<pid>/stat, or (None, None) if gone."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        # /proc/<pid>/stat: pid (comm) state ppid ... — comm may contain spaces
        # and parens, so split from the last ')' to safely skip it.
        rest = data[data.rindex(")") + 2:].split()
        return rest[0], rest[19]  # state, starttime
    except (FileNotFoundError, ProcessLookupError, ValueError, IndexError):
        return None, None


def _proc_starttime(pid: int):
    return _proc_stat(pid)[1]


def _proc_alive(pid: int, expected_starttime: str) -> bool:
    """True only if pid exists, isn't a zombie, and start_time matches what we recorded.
    Zombies count as dead — reap them on the spot so the slot frees up."""
    state, actual = _proc_stat(pid)
    if actual is None or actual != expected_starttime:
        return False
    if state == "Z":
        # Reap so the kernel can recycle the PID.
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            pass
        return False
    return True


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


def _read_script_preview(cmd_list: list) -> dict | None:
    """If cmd_list[1] is an existing .py or .sh file, read and return preview info.
    Returns None when the command doesn't look like a script invocation."""
    if len(cmd_list) < 2:
        return None
    path = cmd_list[1]
    if not (path.endswith(".py") or path.endswith(".sh")):
        return None
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return None
    all_lines  = source.splitlines()
    line_count = len(all_lines)
    too_long   = line_count > 100
    preview_src = "\n".join(all_lines[:100]) if too_long else source
    return {
        "kind":       "script",
        "source":     preview_src,
        "path":       path,
        "line_count": line_count,
        "too_long":   too_long,
    }


def _open_in_editor(path: str):
    """Open a file in the system's default application. Best-effort, never raises."""
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", path], close_fds=True)
        elif os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", path], close_fds=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, FileNotFoundError):
        pass


def _open_text_in_editor(text: str, filename_hint: str = "script.py"):
    """Write text to a temp file and open it. Used for deploy preview where the
    script hasn't been written to its real path yet."""
    try:
        suffix = "." + filename_hint.rsplit(".", 1)[-1] if "." in filename_hint else ".txt"
        fd, tmp = tempfile.mkstemp(prefix="web2local-preview-", suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        _open_in_editor(tmp)
    except OSError:
        pass


# ── Python environment selection ───────────────────────────────────────────────
# A site only ever asks to run scripts with a bare interpreter name like
# "python3". Left alone, subprocess resolves that against the daemon's OWN PATH —
# whatever environment the daemon happened to be launched in, which is usually
# NOT the pixi / conda / venv the user actually develops in. _resolve_interpreter
# rewrites that bare name to an absolute interpreter path chosen, in order:
#
#   1. config["python"]   — explicit user override (interpreter path, env prefix
#                           directory, or a bare name found on PATH)
#   2. a project-local env — .venv / venv / env / .pixi/envs/* discovered by
#                           walking up from the target script's directory
#   3. the daemon's active — $VIRTUAL_ENV or $CONDA_PREFIX (pixi sets the latter)
#      environment
#   4. (nothing matched)  — the command is left untouched, so subprocess falls
#                           back to PATH exactly as before (no behaviour change)
#
# The page never names the interpreter — selection is entirely the daemon-side
# user's, and the resolved path is shown in the approval dialog and audit log
# before anything runs. Only bare python-family names are touched; every other
# command (and any explicit path) passes through unchanged.

# Deliberately NOT included: the Windows "py" launcher (it takes version-selector
# flags like `-3.11` *before* the script, which a plain interpreter can't parse)
# and "pythonw" (the windowless variant — rewriting it to python.exe would pop a
# console). Both are left to resolve via PATH / the launcher's own mechanism.
_PYTHON_NAMES = ("python", "python3", "python2")


def _is_python_command(name: str) -> bool:
    """True if `name` is a bare python interpreter name we should resolve.
    Anything containing a path separator is an explicit choice — left as-is."""
    if not name or os.sep in name or (os.altsep and os.altsep in name):
        return False
    base = name.lower()
    if os.name == "nt" and base.endswith(".exe"):
        base = base[:-4]
    if base in _PYTHON_NAMES:
        return True
    # Versioned interpreters: python3.11, python3.12, python2.7, python3.13t
    # (the trailing `t` is the PEP 703 free-threaded ABI tag).
    return bool(re.fullmatch(r"python[23](?:\.\d{1,2})?t?", base))


def _python_exe_for_prefix(prefix: str) -> str | None:
    """Return the python interpreter inside an env prefix directory, or None."""
    if os.name == "nt":
        candidates = [os.path.join(prefix, "python.exe"),
                      os.path.join(prefix, "Scripts", "python.exe")]
    else:
        candidates = [os.path.join(prefix, "bin", "python"),
                      os.path.join(prefix, "bin", "python3")]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def _interp_from_hint(hint: str) -> str | None:
    """Resolve config["python"], which may be an interpreter path, an env prefix
    directory, or a bare name on PATH. Returns None if nothing usable is found."""
    hint = os.path.expanduser(os.path.expandvars(hint.strip()))
    if not hint:
        return None
    if os.path.isfile(hint) and os.access(hint, os.X_OK):
        return hint
    if os.path.isdir(hint):
        return _python_exe_for_prefix(hint)
    return shutil.which(hint)


def _path_is_trusted(path: str) -> bool:
    """True if `path` is safe to auto-pick an interpreter from. For /run and
    /spawn the page supplies the script path, which seeds the walk-up below — so
    a hostile page could aim discovery at a world-writable dir (/tmp, /dev/shm)
    where any local user has pre-planted a malicious .venv. Reject directories
    that are world-writable or owned by someone other than us (root is fine:
    only root could plant there, and root already owns the box). Group-writable
    is tolerated — it is the norm under the common umask 0002 private-group
    setup. On non-POSIX platforms the ownership/mode model doesn't apply."""
    if not hasattr(os, "geteuid"):
        return True
    try:
        st = os.stat(path)
    except OSError:
        return False
    if st.st_mode & stat.S_IWOTH:
        return False
    if st.st_uid not in (os.geteuid(), 0):
        return False
    return True


def _find_project_python(script_path: str) -> str | None:
    """Walk up from the script's directory looking for a project-local env.
    Only trusted directories (see _path_is_trusted) are searched, so a
    page-supplied script path can't steer discovery into an attacker-writable
    location."""
    try:
        d = os.path.dirname(os.path.abspath(script_path))
    except (OSError, ValueError):
        return None
    prev = None
    while d and d != prev:
        if not _path_is_trusted(d):
            prev, d = d, os.path.dirname(d)
            continue
        for name in (".venv", "venv", "env"):
            exe = _python_exe_for_prefix(os.path.join(d, name))
            if exe:
                return exe
        # Pixi keeps interpreters under .pixi/envs/<name>; prefer 'default'.
        pixi = os.path.join(d, ".pixi", "envs")
        if os.path.isdir(pixi):
            try:
                names = sorted(os.listdir(pixi))
            except OSError:
                names = []
            for n in (["default"] + [x for x in names if x != "default"]):
                exe = _python_exe_for_prefix(os.path.join(pixi, n))
                if exe:
                    return exe
        prev, d = d, os.path.dirname(d)
    return None


def _find_active_python() -> str | None:
    """Use the env the daemon itself was launched in, if any (pixi run / conda
    activate / source venv before starting the daemon all set these)."""
    for var in ("VIRTUAL_ENV", "CONDA_PREFIX"):
        prefix = os.environ.get(var)
        if prefix:
            exe = _python_exe_for_prefix(prefix)
            if exe:
                return exe
    return None


def _detect_python(script_path: str | None = None) -> tuple[str | None, str]:
    """Resolve the interpreter to use, returning (path_or_None, source_label).
    A None path means 'leave the command alone and let PATH resolve it'."""
    raw_override = _get_config().get("python")
    override = raw_override.strip() if isinstance(raw_override, str) else ""
    if override:
        exe = _interp_from_hint(override)
        if exe:
            return exe, "config"
    if script_path:
        exe = _find_project_python(script_path)
        if exe:
            return exe, "project"
    exe = _find_active_python()
    if exe:
        return exe, "active-env"
    return None, "path"


# Interpreter options that consume the following token as their value; the
# script (if any) comes after. `-c`/`-m` instead mean "no script file at all"
# (the remaining tokens are program code / a module name + its args).
_PY_OPTS_WITH_VALUE = ("-W", "-X", "-Q")


def _script_arg(args: list) -> str | None:
    """Return the script-file argument from a python arg list, or None.
    Skips leading interpreter flags so `python -c code`, `python -m mod`, and
    `python -u script.py` are read correctly — only a real script path is used
    to anchor project-local env discovery, never a flag or `-c`/`-m` payload."""
    i = 0
    while i < len(args):
        a = args[i]
        # -c / -m mean "no script file" — both spaced (`-m mod`) and glued
        # (`-mmod`, `-cCODE`) forms; `-` is stdin.
        if a == "-" or a[:2] in ("-c", "-m"):
            return None
        if a.startswith("-"):
            i += 2 if a in _PY_OPTS_WITH_VALUE else 1
            continue
        return a                        # first non-flag token = the script
    return None


def _resolve_interpreter(cmd_list: list) -> list:
    """Rewrite a bare python-family command to the user's selected interpreter.
    Non-python commands and explicit interpreter paths return unchanged."""
    if not cmd_list or not _is_python_command(cmd_list[0]):
        return cmd_list
    # The script path (used only to locate a project-local env near it) is the
    # first non-flag argument. Resolution never touches the args themselves.
    script_path = _script_arg(cmd_list[1:])
    exe, _source = _detect_python(script_path)
    if not exe:
        return cmd_list
    return [exe] + cmd_list[1:]


# ── Python environment provisioning ────────────────────────────────────────────
# A site whose script has nothing to run under (GET /env → interpreter:null) can
# ask the daemon to CREATE one: venv, pixi, or conda. The page only proposes the
# *type*, an optional sandbox name (or a path inside $HOME), and an optional
# package list — it never names the interpreter and never reaches outside $HOME.
# Every request is gated by a native approval dialog. Creation runs as an async
# job (it can take minutes); on success the daemon points config["python"] at the
# new interpreter, so future bare "python3" requests resolve to it.

_VALID_ENV_TYPES = ("venv", "pixi", "conda")
# A package spec the page may pass. Must start alphanumeric (blocks option
# injection like "--target=/etc") and contain no shell/path metacharacters —
# everything runs via argv (no shell), so this is belt-and-suspenders.
_PKG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+\-\[\]<>=!~,*]*")


def _valid_pkg(spec: str) -> bool:
    return isinstance(spec, str) and bool(_PKG_RE.fullmatch(spec))


def _setup_target(name: str, path: str) -> str:
    """Resolve where to create the env. An explicit `path` is confined to $HOME;
    otherwise a sanitized `name` lands in ENVS_DIR. Raises ValueError if neither
    is usable or the path escapes $HOME."""
    home = os.path.realpath(os.path.expanduser("~"))
    if path:
        t = os.path.realpath(os.path.expanduser(os.path.expandvars(path)))
        if t != home and not t.startswith(home + os.sep):
            raise ValueError("path must be inside your home directory")
        if t == home:
            raise ValueError("refusing to create an env directly in your home directory")
        return t
    if name:
        safe = re.sub(r"[^\w.\-]", "_", name).strip("._-")
        if not safe:
            raise ValueError("invalid env name")
        return os.path.join(ENVS_DIR, safe)
    raise ValueError("provide an env name or a path")


def _conda_exe() -> str | None:
    return shutil.which("conda") or shutil.which("mamba") or shutil.which("micromamba")


def _env_plan(env_type: str, target: str, packages: list, base_python: str):
    """Build (steps, interpreter_path) for creating `env_type` at `target`.
    Raises ValueError if the env_type's tool isn't installed."""
    if env_type == "venv":
        if os.name == "nt":
            interp = os.path.join(target, "Scripts", "python.exe")
        else:
            interp = os.path.join(target, "bin", "python")
        steps = [[base_python, "-m", "venv", target]]
        if packages:
            steps.append([interp, "-m", "pip", "install", *packages])
        return steps, interp

    if env_type == "pixi":
        pixi = shutil.which("pixi")
        if not pixi:
            raise ValueError("pixi is not installed (not found on PATH)")
        manifest = os.path.join(target, "pixi.toml")
        interp = os.path.join(target, ".pixi", "envs", "default",
                              ("python.exe" if os.name == "nt" else os.path.join("bin", "python")))
        steps = [[pixi, "init", target],
                 [pixi, "add", "--manifest-path", manifest, "python", *packages]]
        return steps, interp

    if env_type == "conda":
        conda = _conda_exe()
        if not conda:
            raise ValueError("conda is not installed (conda/mamba/micromamba not on PATH)")
        if os.name == "nt":
            interp = os.path.join(target, "python.exe")
        else:
            interp = os.path.join(target, "bin", "python")
        steps = [[conda, "create", "-y", "-p", target, "python", *packages]]
        return steps, interp

    raise ValueError(f"unknown env type: {env_type}")


def _interp_ready(interp: str) -> bool:
    return bool(interp) and os.path.isfile(interp) and os.access(interp, os.X_OK)


# Setup jobs run in their own thread (multi-step recipes), tracked in-memory.
# Growth is human-gated (every job needs an approved dialog) and flood-limited,
# but we still cap the registry so a long-lived daemon doesn't accrete forever.
_setup_lock = threading.Lock()
_setup_jobs: dict = {}
_setup_seq  = [0]
_SETUP_JOBS_MAX = 100


def _setup_persist_python(interpreter: str):
    """Point config["python"] at a freshly created interpreter and save."""
    _mutate_config(lambda c: c.__setitem__("python", interpreter))


def _setup_worker(job_id: str, steps: list, interpreter: str,
                  target: str, env_type: str, origin: str):
    job      = _setup_jobs[job_id]
    log_path = job["log_path"]
    ok       = True
    try:
        with open(log_path, "ab") as log:
            for step in steps:
                log.write(("\n$ " + " ".join(step) + "\n").encode()); log.flush()
                try:
                    r = subprocess.run(step, stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL, timeout=1800)
                except (OSError, subprocess.TimeoutExpired) as e:
                    log.write(f"\n[error] {e}\n".encode()); ok = False; break
                if r.returncode != 0:
                    log.write(f"\n[step failed: exit {r.returncode}]\n".encode())
                    ok = False; break
            if ok and not _interp_ready(interpreter):
                log.write(b"\n[error] interpreter not found after setup\n")
                ok = False
            if ok:
                log.write(f"\n[done] interpreter ready: {interpreter}\n".encode())
    except OSError:
        ok = False

    finished = datetime.datetime.now().isoformat(timespec="seconds")
    # Persist config["python"] BEFORE flipping status to "done", so a client that
    # observes "done" and then queries /env always sees the new interpreter.
    if ok:
        _setup_persist_python(interpreter)
    with _setup_lock:
        job["status"]      = "done" if ok else "failed"
        job["finished_at"] = finished
        if ok:
            job["interpreter"] = interpreter
        else:
            job["error"] = "setup failed — see log"
    if ok:
        _audit("SETUP", origin, [env_type, interpreter], "env_ready")
    else:
        _audit("ERROR", origin, [env_type, target], "setup_failed")


def _setup_start(env_type: str, target: str, packages: list,
                 interpreter: str, steps: list, origin: str) -> dict:
    os.makedirs(PROC_DIR, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe     = re.sub(r"[^\w.\-]", "_", os.path.basename(target)) or "env"
    log_path = os.path.join(PROC_DIR, f"setup-{ts}-{safe}.log")
    # Check-dedup-register atomically so two approved requests for the SAME target
    # can't spawn two workers racing on the same directory.
    with _setup_lock:
        for j in _setup_jobs.values():
            if j["target"] == target and j["status"] == "running":
                return dict(j)   # already building this target — surface that job
        _setup_seq[0] += 1
        jid = str(_setup_seq[0])
        # Bound the registry: drop oldest finished jobs once over the cap.
        if len(_setup_jobs) >= _SETUP_JOBS_MAX:
            done = [k for k, v in _setup_jobs.items() if v["status"] != "running"]
            for k in done[:len(_setup_jobs) - _SETUP_JOBS_MAX + 1]:
                _setup_jobs.pop(k, None)
        with open(log_path, "w") as f:
            f.write(f"web2local environment setup\n  type     : {env_type}\n"
                    f"  target   : {target}\n  packages : {', '.join(packages) or '(none)'}\n")
        job = {
            "id":         jid,
            "type":       env_type,
            "target":     target,
            "packages":   packages,
            "status":     "running",
            "log_path":   log_path,
            "interpreter": None,
            "error":      "",
            "started_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "finished_at": None,
            "origin":     origin,
        }
        _setup_jobs[jid] = job
    threading.Thread(target=_setup_worker,
                     args=(jid, steps, interpreter, target, env_type, origin),
                     daemon=True).start()
    return job


def _request_setup_approval(origin: str, env_type: str, target: str,
                            packages: list, steps: list) -> bool:
    """Queue an env-setup approval dialog and block until the user responds."""
    if not _flood_check(origin):
        _audit("FLOOD_BLOCKED", origin, [env_type, target], "flood_rate_limit")
        return False
    event  = threading.Event()
    result = [False]
    summary = [f"{env_type} environment → {target.replace(os.path.expanduser('~'), '~')}"]
    _dialog_queue.put((origin, summary, event, result, {
        "kind":     "setup",
        "env_type": env_type,
        "target":   target,
        "packages": packages,
        "steps":    steps,
    }))
    event.wait(timeout=135)
    return result[0]


# ── Agent delivery ───────────────────────────────────────────────────────────

def _deploy_resolve(filename: str, sha256: str) -> str:
    """Return the canonical on-disk path for a deployed script."""
    safe = re.sub(r"[^\w\-.]", "_", os.path.basename(filename)) or "agent.py"
    return os.path.join(AGENTS_DIR, f"{sha256[:8]}-{safe}")


def _deploy_write(source: str, sha256: str, filename: str) -> tuple:
    """Verify SHA-256, write file if needed, return (dest_path, was_written)."""
    actual = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if actual != sha256.lower():
        raise ValueError(f"SHA-256 mismatch: provided {sha256[:8]}…, content hashes to {actual[:8]}…")

    dest = _deploy_resolve(filename, sha256)
    os.makedirs(AGENTS_DIR, exist_ok=True)

    # Idempotent: skip write if the exact bytes already exist.
    if os.path.exists(dest):
        with open(dest, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() == sha256.lower():
                return dest, False

    with open(dest, "w", encoding="utf-8") as f:
        f.write(source)
    return dest, True


# ── Agents manifest ───────────────────────────────────────────────────────────
# Tracks every script deployed via /deploy so the user can see and revoke them.

AGENTS_MANIFEST = os.path.join(CONFIG_DIR, "agents.json")


def _agents_load() -> list:
    if not os.path.exists(AGENTS_MANIFEST):
        return []
    try:
        with open(AGENTS_MANIFEST) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _agents_save(entries: list):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(AGENTS_MANIFEST, "w") as f:
        json.dump(entries, f, indent=2)


def _agents_record(sha256: str, filename: str, dest_path: str, origin: str):
    entries = [e for e in _agents_load() if e.get("sha256") != sha256]
    entries.append({
        "sha256":      sha256,
        "filename":    filename,
        "dest_path":   dest_path,
        "origin":      origin,
        "deployed_at": datetime.datetime.now().isoformat(timespec="seconds"),
    })
    _agents_save(entries)


def _agents_list_live() -> list:
    """Return manifest filtered to entries whose files still exist on disk."""
    entries = _agents_load()
    live = [e for e in entries if os.path.exists(e.get("dest_path", ""))]
    if len(live) != len(entries):
        _agents_save(live)
    return live


def _agents_delete(sha256: str) -> bool:
    """Delete a deployed script file and its manifest entry. Returns True if found."""
    entries = _agents_load()
    entry = next((e for e in entries if e.get("sha256") == sha256), None)
    if not entry:
        return False
    dest = entry.get("dest_path", "")
    if os.path.exists(dest):
        try:
            os.remove(dest)
        except OSError:
            pass
    _agents_save([e for e in entries if e.get("sha256") != sha256])
    return True


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
                extra = item[4] if len(item) == 5 else None
                if extra and extra.get("kind") == "deploy":
                    _show_deploy_tk_dialog(tk, root, item)
                elif extra and extra.get("kind") == "handshake":
                    _show_handshake_tk_dialog(tk, root, item)
                elif extra and extra.get("kind") == "setup":
                    _show_setup_tk_dialog(tk, root, item)
                else:
                    _show_tk_dialog(tk, root, item)
            except queue.Empty:
                pass
        root.after(100, _check)

    root.after(100, _check)
    root.mainloop()


def _show_tk_dialog(tk, root, item):
    global _dialog_active
    if len(item) == 5:
        origin, cmd_list, event, result, preview = item
    else:
        origin, cmd_list, event, result = item
        preview = None

    alive  = [True]
    paused = [False]

    dlg = tk.Toplevel(root)
    dlg.title("web2local — Command Approval")
    dlg.resizable(True, True)
    dlg.attributes("-topmost", True)
    dlg.minsize(720, 460)

    # Header bar
    hdr = tk.Frame(dlg, bg="#1a1a2e", pady=14)
    hdr.pack(fill="x")
    tk.Label(hdr, text="⚠  Command Approval Required",
             bg="#1a1a2e", fg="white", font=("Arial", 13, "bold")).pack()

    body = tk.Frame(dlg, bg="#0d1117", padx=22, pady=12)
    body.pack(fill="both", expand=True)

    tk.Label(body, text="Requesting website:", font=("Arial", 11, "bold"), fg="#e6edf3", bg=body["bg"], anchor="w").pack(fill="x")
    tk.Label(body, text=origin, fg="#f0a050", font=("Courier", 11, "bold"), bg=body["bg"], anchor="w").pack(fill="x", pady=(0, 12))

    tk.Label(body, text="Command to execute:", font=("Arial", 11, "bold"), fg="#e6edf3", bg=body["bg"], anchor="w").pack(fill="x")

    frm = tk.Frame(body, relief="sunken", bd=1)
    frm.pack(fill="x", pady=(4, 0))

    txt  = tk.Text(frm, font=("Courier", 10), height=4, wrap="none",
                   bg="#0d1117", fg="#f0f6fc", insertbackground="#f0f6fc",
                   padx=10, pady=8)
    sb_y = tk.Scrollbar(frm, orient="vertical",   command=txt.yview)
    sb_x = tk.Scrollbar(frm, orient="horizontal", command=txt.xview)
    txt.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
    display = " ".join(
        f'"{a}"' if (" " in a or not a) else a for a in cmd_list
    )
    txt.insert("end", display)
    txt.config(state="disabled")
    sb_y.pack(side="right",  fill="y")
    sb_x.pack(side="bottom", fill="x")
    txt.pack(fill="both", expand=True)

    tk.Label(body,
             text="Read the full command carefully. Scroll right if it is long.",
             fg="#cc0000", bg=body["bg"], font=("Arial", 9, "italic"), anchor="w").pack(fill="x", pady=(8, 0))

    # ── Script preview (optional) ──────────────────────────────────────
    if preview:
        tk.Frame(body, bg="#30363d", height=1).pack(fill="x", pady=(12, 10))

        toggle_row = tk.Frame(body, bg=body["bg"])
        toggle_row.pack(fill="x")

        pf       = tk.Frame(body, bg=body["bg"])
        pf_shown = [False]

        # Path label (above the source box) — shows what file is being previewed
        path_row = tk.Frame(pf, bg=body["bg"])
        path_row.pack(fill="x", pady=(0, 4))
        tk.Label(path_row, text="File:", font=("Arial", 10, "bold"),
                 fg="#e6edf3", bg=body["bg"]).pack(side="left")
        tk.Label(path_row, text=preview["path"].replace(os.path.expanduser("~"), "~"),
                 font=("Courier", 10), fg="#a5d6ff", bg=body["bg"]).pack(side="left", padx=(6, 0))

        src_box = tk.Frame(pf, relief="solid", bd=1, bg="#30363d")
        src_box.pack(fill="both", expand=True)

        src_txt = tk.Text(src_box, font=("Courier", 11), height=18, wrap="none",
                          bg="#0d1117", fg="#f0f6fc",
                          insertbackground="#f0f6fc",
                          padx=12, pady=10, spacing1=1, spacing3=1, bd=0)
        sb_sy   = tk.Scrollbar(src_box, orient="vertical",   command=src_txt.yview)
        sb_sx   = tk.Scrollbar(src_box, orient="horizontal", command=src_txt.xview)
        src_txt.configure(yscrollcommand=sb_sy.set, xscrollcommand=sb_sx.set)

        # Insert source with line numbers for readability
        src_lines = preview["source"].splitlines() or [""]
        width     = len(str(len(src_lines)))
        for i, ln in enumerate(src_lines, 1):
            src_txt.insert("end", f"{str(i).rjust(width)} │ ", "ln")
            src_txt.insert("end", ln + "\n")
        if preview["too_long"]:
            src_txt.insert("end",
                f"\n… {preview['line_count'] - 100} more lines not shown. "
                "Click 'Open in editor' to view the full file.", "note")
        src_txt.tag_configure("ln",   foreground="#6e7681")
        src_txt.tag_configure("note", foreground="#e3b341", font=("Courier", 10, "italic"))
        src_txt.config(state="disabled")
        sb_sy.pack(side="right",  fill="y")
        sb_sx.pack(side="bottom", fill="x")
        src_txt.pack(fill="both", expand=True)

        def _toggle_preview():
            if pf_shown[0]:
                pf.pack_forget()
                toggle_btn.config(text=f"▶  Show script  ({preview['line_count']} lines)")
                pf_shown[0] = False
            else:
                pf.pack(fill="both", expand=True, pady=(8, 0))
                toggle_btn.config(text=f"▼  Hide script  ({preview['line_count']} lines)")
                pf_shown[0] = True

        toggle_btn = tk.Button(
            toggle_row,
            text=f"▶  Show script  ({preview['line_count']} lines)",
            command=_toggle_preview,
            bg=body["bg"], fg="#79c0ff", relief="flat",
            font=("Arial", 11, "bold"), anchor="w", cursor="hand2",
            activebackground=body["bg"], activeforeground="#a5d6ff",
            padx=0,
        )
        toggle_btn.pack(side="left")

        # "Open in editor" — uses the OS default for .py / .sh files
        def _open_file():
            _open_in_editor(preview["path"])
        tk.Button(
            toggle_row, text="↗  Open in editor", command=_open_file,
            bg="#21262d", fg="#79c0ff", relief="flat",
            font=("Arial", 10, "bold"), padx=12, pady=4, cursor="hand2",
            activebackground="#30363d", activeforeground="#a5d6ff",
        ).pack(side="left", padx=(12, 0))

        if preview["too_long"]:
            def _pause():
                paused[0] = True
                pause_btn.config(state="disabled",
                                 text="⏸  Paused — click Allow or Deny when ready")
            pause_btn = tk.Button(
                toggle_row, text="⏸  Pause auto-deny", command=_pause,
                bg="#2d3748", fg="#e3b341", relief="flat",
                font=("Arial", 10, "bold"), padx=12, pady=4, cursor="hand2",
                activebackground="#3d4758", activeforeground="#f6c443",
            )
            pause_btn.pack(side="right")

    # ── Timer ─────────────────────────────────────────────────────────
    remaining = [120]
    timer_var = tk.StringVar(value="Auto-deny in 120 s")
    tk.Label(body, textvariable=timer_var, fg="#888", bg=body["bg"],
             font=("Arial", 8), anchor="w").pack(fill="x", pady=(8, 0))

    def _tick():
        if not alive[0] or paused[0]:
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

    btn = tk.Frame(dlg, bg="#0d1117", padx=22, pady=14)
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


def _show_deploy_tk_dialog(tk, root, item):
    """Deploy-specific approval dialog: shows filename, full SHA-256, destination, command, and source."""
    global _dialog_active
    origin, cmd_list, event, result, meta = item
    filename  = meta["filename"]
    sha256    = meta["sha256"]
    dest_path = meta["dest_path"]
    source    = meta.get("source", "")
    alive     = [True]
    paused    = [False]

    dlg = tk.Toplevel(root)
    dlg.title("web2local — Script Deploy & Run Approval")
    dlg.resizable(True, True)
    dlg.attributes("-topmost", True)
    dlg.minsize(760, 620)

    # Header
    hdr = tk.Frame(dlg, bg="#2d1a4a", pady=14)
    hdr.pack(fill="x")
    tk.Label(hdr, text="⚠  Script Deploy & Run — Approval Required",
             bg="#2d1a4a", fg="white", font=("Arial", 13, "bold")).pack()

    body = tk.Frame(dlg, bg="#0d1117", padx=22, pady=12)
    body.pack(fill="both", expand=True)

    # Requesting site
    tk.Label(body, text="Requesting website:", font=("Arial", 11, "bold"), fg="#e6edf3", bg=body["bg"], anchor="w").pack(fill="x")
    tk.Label(body, text=origin, fg="#f0a050", font=("Courier", 11, "bold"), bg=body["bg"], anchor="w").pack(fill="x", pady=(0, 10))

    # File info grid
    info = tk.Frame(body, bg=body["bg"])
    info.pack(fill="x", pady=(0, 10))

    def _row(label, value, selectable=False):
        tk.Label(info, text=label, font=("Arial", 10, "bold"), anchor="w",
                 fg="#e6edf3", bg=body["bg"], width=14, justify="left").grid(
            row=_row.n, column=0, sticky="nw", pady=4)
        if selectable:
            e = tk.Entry(info, font=("Courier", 10, "bold"), bg="#0d1117", fg="#a5d6ff",
                         relief="flat", readonlybackground="#0d1117", width=64,
                         insertbackground="#a5d6ff")
            e.insert(0, value)
            e.config(state="readonly")
            e.grid(row=_row.n, column=1, sticky="ew", padx=(8, 0), pady=4)
        else:
            tk.Label(info, text=value, font=("Courier", 10), anchor="w",
                     fg="#f0f6fc", bg=body["bg"], wraplength=520, justify="left").grid(
                row=_row.n, column=1, sticky="w", padx=(8, 0), pady=4)
        _row.n += 1

    _row.n = 0
    info.columnconfigure(1, weight=1)
    _row("File:", filename)
    _row("SHA-256:", sha256, selectable=True)
    _row("Destination:", dest_path.replace(os.path.expanduser("~"), "~"))

    # Command box
    tk.Label(body, text="Command to run:", font=("Arial", 11, "bold"),
             fg="#e6edf3", bg=body["bg"], anchor="w").pack(fill="x")
    frm = tk.Frame(body, relief="solid", bd=1, bg="#30363d")
    frm.pack(fill="x", pady=(4, 0))

    txt  = tk.Text(frm, font=("Courier", 11), height=4, wrap="none",
                   bg="#0d1117", fg="#f0f6fc", insertbackground="#f0f6fc",
                   padx=10, pady=8, bd=0)
    sb_x = tk.Scrollbar(frm, orient="horizontal", command=txt.xview)
    txt.configure(xscrollcommand=sb_x.set)
    display = " ".join(
        f'"{a}"' if (" " in a or not a) else a for a in cmd_list
    )
    txt.insert("end", display)
    txt.config(state="disabled")
    sb_x.pack(side="bottom", fill="x")
    txt.pack(fill="both", expand=True)

    # ── Source preview (always shown for deploy) ──────────────────────
    if source:
        tk.Frame(body, bg="#30363d", height=1).pack(fill="x", pady=(12, 10))

        src_all_lines = source.splitlines() or [""]
        line_count    = len(src_all_lines)
        too_long      = line_count > 100
        display_lines = src_all_lines[:100] if too_long else src_all_lines

        preview_row = tk.Frame(body, bg=body["bg"])
        preview_row.pack(fill="x")

        pf       = tk.Frame(body, bg=body["bg"])
        pf_shown = [True]   # expanded by default for deploy

        src_box = tk.Frame(pf, relief="solid", bd=1, bg="#30363d")
        src_box.pack(fill="both", expand=True)

        src_txt = tk.Text(src_box, font=("Courier", 11), height=18, wrap="none",
                          bg="#0d1117", fg="#f0f6fc",
                          insertbackground="#f0f6fc",
                          padx=12, pady=10, spacing1=1, spacing3=1, bd=0)
        sb_sy   = tk.Scrollbar(src_box, orient="vertical",   command=src_txt.yview)
        sb_sx   = tk.Scrollbar(src_box, orient="horizontal", command=src_txt.xview)
        src_txt.configure(yscrollcommand=sb_sy.set, xscrollcommand=sb_sx.set)

        num_width = len(str(len(display_lines)))
        for i, ln in enumerate(display_lines, 1):
            src_txt.insert("end", f"{str(i).rjust(num_width)} │ ", "ln")
            src_txt.insert("end", ln + "\n")
        if too_long:
            src_txt.insert("end",
                f"\n… {line_count - 100} more lines not shown. "
                "Click 'Open in editor' to review the full script.", "note")
        src_txt.tag_configure("ln",   foreground="#6e7681")
        src_txt.tag_configure("note", foreground="#e3b341", font=("Courier", 10, "italic"))
        src_txt.config(state="disabled")
        sb_sy.pack(side="right",  fill="y")
        sb_sx.pack(side="bottom", fill="x")
        src_txt.pack(fill="both", expand=True)
        pf.pack(fill="both", expand=True, pady=(8, 0))

        def _toggle_src():
            if pf_shown[0]:
                pf.pack_forget()
                toggle_src_btn.config(text=f"▶  Show script source  ({line_count} lines)")
                pf_shown[0] = False
            else:
                pf.pack(fill="both", expand=True, pady=(8, 0))
                toggle_src_btn.config(text=f"▼  Hide script source  ({line_count} lines)")
                pf_shown[0] = True

        toggle_src_btn = tk.Button(
            preview_row,
            text=f"▼  Hide script source  ({line_count} lines)",
            command=_toggle_src,
            bg=body["bg"], fg="#79c0ff", relief="flat",
            font=("Arial", 11, "bold"), anchor="w", cursor="hand2",
            activebackground=body["bg"], activeforeground="#a5d6ff",
            padx=0,
        )
        toggle_src_btn.pack(side="left")

        # "Open in editor" — writes source to a temp file and opens it
        def _open_deploy_src():
            _open_text_in_editor(source, filename)
        tk.Button(
            preview_row, text="↗  Open in editor", command=_open_deploy_src,
            bg="#21262d", fg="#79c0ff", relief="flat",
            font=("Arial", 10, "bold"), padx=12, pady=4, cursor="hand2",
            activebackground="#30363d", activeforeground="#a5d6ff",
        ).pack(side="left", padx=(12, 0))

        if too_long:
            def _pause_deploy():
                paused[0] = True
                pause_deploy_btn.config(state="disabled",
                                        text="⏸  Paused — click Allow or Deny when ready")
            pause_deploy_btn = tk.Button(
                preview_row, text="⏸  Pause auto-deny", command=_pause_deploy,
                bg="#2d3748", fg="#e3b341", relief="flat",
                font=("Arial", 10, "bold"), padx=12, pady=4, cursor="hand2",
                activebackground="#3d4758", activeforeground="#f6c443",
            )
            pause_deploy_btn.pack(side="right")

    tk.Label(body,
             text="Verify the SHA-256 above against what the website published before approving.",
             fg="#cc0000", bg=body["bg"], font=("Arial", 9, "italic"), anchor="w").pack(fill="x", pady=(8, 0))

    remaining = [120]
    timer_var = tk.StringVar(value="Auto-deny in 120 s")
    tk.Label(body, textvariable=timer_var, fg="#888", bg=body["bg"], font=("Arial", 8), anchor="w").pack(fill="x")

    def _tick():
        if not alive[0] or paused[0]:
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

    btn = tk.Frame(dlg, bg="#0d1117", padx=22, pady=14)
    btn.pack(fill="x")
    tk.Button(btn, text="Deny", command=_deny,
              bg="#c0392b", fg="white", font=("Arial", 10, "bold"),
              width=12, relief="flat", pady=6).pack(side="left")
    tk.Button(btn, text="Allow — Write & Run", command=_approve,
              bg="#6f42c1", fg="white", font=("Arial", 10, "bold"),
              width=20, relief="flat", pady=6).pack(side="right")

    dlg.update_idletasks()
    sw, sh = dlg.winfo_screenwidth(), dlg.winfo_screenheight()
    w,  h  = dlg.winfo_width(),       dlg.winfo_height()
    dlg.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")


def _show_setup_tk_dialog(tk, root, item):
    """Env-setup approval dialog: shows env type, target, packages, and the exact
    commands the daemon will run to create the environment."""
    global _dialog_active
    origin, _summary, event, result, meta = item
    env_type = meta["env_type"]
    target   = meta["target"]
    packages = meta.get("packages") or []
    steps    = meta.get("steps") or []
    alive    = [True]

    dlg = tk.Toplevel(root)
    dlg.title("web2local — Python Environment Setup")
    dlg.resizable(True, True)
    dlg.attributes("-topmost", True)
    dlg.minsize(720, 460)

    hdr = tk.Frame(dlg, bg="#143d2b", pady=14)
    hdr.pack(fill="x")
    tk.Label(hdr, text="🐍  Create Python Environment — Approval Required",
             bg="#143d2b", fg="white", font=("Arial", 13, "bold")).pack()

    body = tk.Frame(dlg, bg="#0d1117", padx=22, pady=12)
    body.pack(fill="both", expand=True)

    tk.Label(body, text="Requesting website:", font=("Arial", 11, "bold"),
             fg="#e6edf3", bg=body["bg"], anchor="w").pack(fill="x")
    tk.Label(body, text=origin, fg="#f0a050", font=("Courier", 11, "bold"),
             bg=body["bg"], anchor="w").pack(fill="x", pady=(0, 10))

    info = tk.Frame(body, bg=body["bg"])
    info.pack(fill="x", pady=(0, 10))
    info.columnconfigure(1, weight=1)

    def _row(label, value):
        tk.Label(info, text=label, font=("Arial", 10, "bold"), anchor="w",
                 fg="#e6edf3", bg=body["bg"], width=12).grid(
            row=_row.n, column=0, sticky="nw", pady=4)
        tk.Label(info, text=value, font=("Courier", 10), anchor="w",
                 fg="#f0f6fc", bg=body["bg"], wraplength=520, justify="left").grid(
            row=_row.n, column=1, sticky="w", padx=(8, 0), pady=4)
        _row.n += 1
    _row.n = 0
    _row("Type:", env_type)
    _row("Target:", target.replace(os.path.expanduser("~"), "~"))
    _row("Packages:", ", ".join(packages) or "(none — python only)")

    tk.Label(body, text="Commands to run:", font=("Arial", 11, "bold"),
             fg="#e6edf3", bg=body["bg"], anchor="w").pack(fill="x")
    frm = tk.Frame(body, relief="solid", bd=1, bg="#30363d")
    frm.pack(fill="both", expand=True, pady=(4, 0))
    txt  = tk.Text(frm, font=("Courier", 10), height=6, wrap="none",
                   bg="#0d1117", fg="#f0f6fc", insertbackground="#f0f6fc",
                   padx=10, pady=8, bd=0)
    sb_y = tk.Scrollbar(frm, orient="vertical",   command=txt.yview)
    sb_x = tk.Scrollbar(frm, orient="horizontal", command=txt.xview)
    txt.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
    for s in steps:
        txt.insert("end", "$ " + " ".join(
            f'"{a}"' if (" " in a or not a) else a for a in s) + "\n")
    txt.config(state="disabled")
    sb_y.pack(side="right",  fill="y")
    sb_x.pack(side="bottom", fill="x")
    txt.pack(fill="both", expand=True)

    tk.Label(body,
             text="This creates a new environment and may download packages from the internet.",
             fg="#cc0000", bg=body["bg"], font=("Arial", 9, "italic"), anchor="w").pack(fill="x", pady=(8, 0))

    remaining = [120]
    timer_var = tk.StringVar(value="Auto-deny in 120 s")
    tk.Label(body, textvariable=timer_var, fg="#888", bg=body["bg"],
             font=("Arial", 8), anchor="w").pack(fill="x")

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

    dlg.protocol("WM_DELETE_WINDOW", _deny)

    btn = tk.Frame(dlg, bg="#0d1117", padx=22, pady=14)
    btn.pack(fill="x")
    tk.Button(btn, text="Deny", command=_deny,
              bg="#c0392b", fg="white", font=("Arial", 10, "bold"),
              width=12, relief="flat", pady=6).pack(side="left")
    tk.Button(btn, text="Allow — Create env", command=_approve,
              bg="#1a6b3a", fg="white", font=("Arial", 10, "bold"),
              width=20, relief="flat", pady=6).pack(side="right")

    dlg.update_idletasks()
    sw, sh = dlg.winfo_screenwidth(), dlg.winfo_screenheight()
    w,  h  = dlg.winfo_width(),       dlg.winfo_height()
    dlg.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")


def _show_handshake_tk_dialog(tk, root, item):
    """First-contact dialog: a new site wants to connect. User picks trust level."""
    global _dialog_active
    origin, _, event, result, _ = item
    alive = [True]

    dlg = tk.Toplevel(root)
    dlg.title("web2local — Site Connection Request")
    dlg.resizable(False, False)
    dlg.attributes("-topmost", True)
    dlg.minsize(560, 260)

    hdr = tk.Frame(dlg, bg="#1a2e1a", pady=14)
    hdr.pack(fill="x")
    tk.Label(hdr, text="New Site Wants to Connect",
             bg="#1a2e1a", fg="white", font=("Arial", 13, "bold")).pack()

    body = tk.Frame(dlg, bg="#0d1117", padx=22, pady=12)
    body.pack(fill="both", expand=True)

    tk.Label(body, text="Site:", font=("Arial", 11, "bold"),
             fg="#e6edf3", bg=body["bg"], anchor="w").pack(fill="x")
    tk.Label(body, text=origin, fg="#f0a050", font=("Courier", 11, "bold"),
             bg=body["bg"], anchor="w").pack(fill="x", pady=(0, 14))

    tk.Label(body,
             text="This site is not on your whitelist or graylist. How much do you trust it?",
             fg="#e6edf3", bg=body["bg"], font=("Arial", 10), anchor="w", wraplength=500).pack(fill="x")

    def _choose(level):
        global _dialog_active
        if not alive[0]:
            return
        alive[0]       = False
        result[0]      = level
        _dialog_active = False
        event.set()
        dlg.destroy()

    dlg.protocol("WM_DELETE_WINDOW", lambda: _choose(None))

    btn = tk.Frame(dlg, bg="#0d1117", padx=22, pady=14)
    btn.pack(fill="x")

    tk.Button(btn, text="Block", command=lambda: _choose(None),
              bg="#c0392b", fg="white", font=("Arial", 10, "bold"),
              width=8, relief="flat", pady=6).pack(side="left")
    tk.Button(btn, text="Session only",
              command=lambda: _choose("session"),
              bg="#2d5a8e", fg="white", font=("Arial", 10, "bold"),
              relief="flat", padx=14, pady=6).pack(side="left", padx=(8, 0))
    tk.Button(btn, text="Always graylist",
              command=lambda: _choose("graylist"),
              bg="#7a6000", fg="white", font=("Arial", 10, "bold"),
              relief="flat", padx=14, pady=6).pack(side="left", padx=(8, 0))
    tk.Button(btn, text="Always whitelist",
              command=lambda: _choose("whitelist"),
              bg="#1a6b3a", fg="white", font=("Arial", 10, "bold"),
              relief="flat", padx=14, pady=6).pack(side="right")

    tk.Label(body,
             text="Session: trust until the daemon restarts. Graylist: prompt every command. Whitelist: run without prompts.",
             fg="#666", bg=body["bg"], font=("Arial", 8, "italic"), anchor="w",
             wraplength=500).pack(fill="x", pady=(10, 0))

    dlg.update_idletasks()
    sw, sh = dlg.winfo_screenwidth(), dlg.winfo_screenheight()
    w,  h  = dlg.winfo_width(),       dlg.winfo_height()
    dlg.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")


def _run_terminal_loop():
    """Fallback when tkinter is unavailable."""
    while True:
        try:
            item = _dialog_queue.get(timeout=1)
            sep  = "=" * 60
            if len(item) == 5:
                origin, cmd_list, event, result, meta = item
                kind = meta.get("kind", "deploy")
                if kind == "handshake":
                    print(f"\n{sep}")
                    print("[web2local] SITE CONNECTION REQUEST")
                    print(sep)
                    print(f"  Site: {origin}")
                    print("  Options:")
                    print("    (1) Block")
                    print("    (2) Session graylist (trust until daemon restarts)")
                    print("    (3) Always graylist  (prompt before each command)")
                    print("    (4) Always whitelist (run without prompts)")
                    print(sep)
                    try:
                        ans = input("  Choice (1-4): ").strip()
                        result[0] = {
                            "1": None, "2": "session",
                            "3": "graylist", "4": "whitelist",
                        }.get(ans)
                    except (EOFError, KeyboardInterrupt):
                        result[0] = None
                        print("\n[blocked]")
                    event.set()
                    continue
                elif kind == "deploy":
                    print(f"\n{sep}")
                    print("[web2local] SCRIPT DEPLOY & RUN APPROVAL REQUIRED")
                    print(sep)
                    print(f"  Site        : {origin}")
                    print(f"  File        : {meta['filename']}")
                    print(f"  SHA-256     : {meta['sha256']}")
                    print(f"  Destination : {meta['dest_path']}")
                    print(f"  Command     : {' '.join(cmd_list)}")
                    src = meta.get("source", "")
                    if src:
                        lines = src.splitlines()[:20]
                        print(f"\n  --- Script preview (first {len(lines)} lines) ---")
                        for ln in lines:
                            print(f"  {ln}")
                        print(f"  ---")
                    print(sep)
                    print("  Verify the SHA-256 before answering.")
                elif kind == "setup":
                    print(f"\n{sep}")
                    print("[web2local] PYTHON ENV SETUP APPROVAL REQUIRED")
                    print(sep)
                    print(f"  Site     : {origin}")
                    print(f"  Type     : {meta['env_type']}")
                    print(f"  Target   : {meta['target']}")
                    print(f"  Packages : {', '.join(meta.get('packages') or []) or '(none)'}")
                    print("  Steps:")
                    for s in meta.get("steps", []):
                        print(f"    $ {' '.join(s)}")
                    print(sep)
                else:  # kind == "script"
                    origin, cmd_list, event, result, preview = item
                    print(f"\n{sep}")
                    print("[web2local] COMMAND APPROVAL REQUIRED")
                    print(sep)
                    print(f"  Site   : {origin}")
                    print(f"  Command: {' '.join(cmd_list)}")
                    src = preview.get("source", "")
                    if src:
                        lines = src.splitlines()[:20]
                        print(f"\n  --- Script preview (first {len(lines)} of "
                              f"{preview['line_count']} lines) ---")
                        for ln in lines:
                            print(f"  {ln}")
                        print(f"  ---")
                    print(sep)
            else:
                origin, cmd_list, event, result = item
                display = " ".join(cmd_list)
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


def _request_approval(origin: str, cmd_list: list,
                       preview: dict | None = None) -> bool:
    """Queue a command approval dialog and block until the user responds.
    Pass preview=dict (from _read_script_preview) to show the script source."""
    if not _flood_check(origin):
        _audit("FLOOD_BLOCKED", origin, cmd_list, "flood_rate_limit")
        return False
    event  = threading.Event()
    result = [False]
    if preview:
        _dialog_queue.put((origin, cmd_list, event, result, preview))
    else:
        _dialog_queue.put((origin, cmd_list, event, result))
    event.wait(timeout=135)
    return result[0]


def _request_deploy_approval(origin: str, filename: str, sha256: str,
                              dest_path: str, cmd_list: list,
                              source: str = "") -> bool:
    """Queue a deploy approval dialog and block until the user responds.
    Always shown — even for whitelist origins — because writing executable code
    to disk is categorically more powerful than running a known command."""
    if not _flood_check(origin):
        _audit("FLOOD_BLOCKED", origin, [filename], "flood_rate_limit")
        return False
    event  = threading.Event()
    result = [False]
    _dialog_queue.put((origin, cmd_list, event, result, {
        "kind":      "deploy",
        "filename":  filename,
        "sha256":    sha256,
        "dest_path": dest_path,
        "source":    source,
    }))
    event.wait(timeout=135)
    return result[0]


def _request_handshake(origin: str):
    """Queue a handshake dialog and block until the user responds.
    Returns trust level: 'session' | 'graylist' | 'whitelist' | None (blocked)."""
    event  = threading.Event()
    result = [None]
    _dialog_queue.put((origin, None, event, result, {"kind": "handshake"}))
    event.wait(timeout=135)
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
        if _is_session_trusted(origin):
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
        # Execution endpoints require origin to be in a list.
        # Config endpoints have no such restriction — that's how you add yourself.
        if path in ("/run", "/spawn", "/stop", "/deploy") and not self._classify(origin):
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

        if path == "/agents":
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}); return
            _send_json(self, 200, {"agents": _agents_list_live()}, origin)
            return

        # ── /env — report which python interpreter a "python3" request maps to ──
        # Diagnostic only. Reflects the script-independent decision (config →
        # active env → PATH fallback); project-local envs are resolved per script
        # at run time, so they don't appear here. Unlike /config this exposes the
        # daemon's own env-var values (VIRTUAL_ENV/CONDA_PREFIX, hence home-dir
        # layout), so it is restricted to origins already trusted to run commands
        # — they could read the same via /run anyway, and untrusted pages can't
        # enumerate it.
        if path == "/env":
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}); return
            if not self._classify(origin):
                _send_json(self, 403, {"error": "origin not in whitelist or graylist"}, origin)
                return
            cfg_python = _get_config().get("python")
            exe, source = _detect_python(None)
            _send_json(self, 200, {
                "interpreter":   exe,            # null → falls back to PATH python3
                "source":        source,         # config | active-env | path
                "config_python": cfg_python if isinstance(cfg_python, str) else "",
                "active": {
                    "VIRTUAL_ENV":  os.environ.get("VIRTUAL_ENV", ""),
                    "CONDA_PREFIX": os.environ.get("CONDA_PREFIX", ""),
                },
            }, origin)
            return

        # ── /setup-env/status — poll an async env-creation job ──
        if path == "/setup-env/status":
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}); return
            if not self._classify(origin):
                _send_json(self, 403, {"error": "origin not in whitelist or graylist"}, origin)
                return
            from urllib.parse import urlparse, parse_qs
            jid = parse_qs(urlparse(full).query).get("job", [""])[0]
            with _setup_lock:
                job = _setup_jobs.get(jid)
                job = dict(job) if job else None
            # Scope to the owning origin. A foreign job reads as 404 (not 403) so a
            # probing site can't use sequential IDs as an existence oracle on
            # another trusted origin's jobs.
            if not job or job.get("origin", "").rstrip("/") != origin.rstrip("/"):
                _send_json(self, 404, {"error": "unknown job"}, origin); return
            _send_json(self, 200, {
                "job_id":      job["id"],
                "type":        job["type"],
                "target":      job["target"],
                "packages":    job["packages"],
                "status":      job["status"],        # running | done | failed
                "interpreter": job["interpreter"],
                "error":       job["error"],
                "started_at":  job["started_at"],
                "finished_at": job["finished_at"],
                "tail":        _proc_tail(job["log_path"], 200),
            }, origin)
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
            if not url or url == "null":
                _send_json(self, 400, {"error": "missing or invalid origin"}, origin); return
            list_key  = "whitelist" if path == "/config/whitelist" else "graylist"
            other_key = "graylist"  if list_key == "whitelist"     else "whitelist"
            def _apply(cfg):
                cfg[other_key] = [o for o in cfg[other_key] if o.rstrip("/") != url]
                if url not in [o.rstrip("/") for o in cfg[list_key]]:
                    cfg[list_key].append(url)
            _mutate_config(_apply)
            _send_json(self, 200, {"status": "added", "list": list_key, "origin": url}, origin)
            return

        if path == "/config/remove":
            url = data.get("origin", "").rstrip("/")
            def _apply(cfg):
                cfg["whitelist"] = [o for o in cfg["whitelist"] if o.rstrip("/") != url]
                cfg["graylist"]  = [o for o in cfg["graylist"]  if o.rstrip("/") != url]
            _mutate_config(_apply)
            _send_json(self, 200, {"status": "removed"}, origin)
            return

        # ── /handshake — first-contact trust request from an unknown site ──

        if path == "/handshake":
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}, origin); return
            req_origin = data.get("origin", origin).rstrip("/")
            if not req_origin or req_origin == "null":
                _send_json(self, 400, {"error": "invalid origin"}, origin); return
            existing = self._classify(req_origin)
            if existing:
                _send_json(self, 200,
                           {"status": "already_trusted", "level": existing}, origin)
                return
            level = _request_handshake(req_origin)
            if level is None:
                _send_json(self, 403, {"error": "connection blocked by user"}, origin)
                _audit("BLOCKED", req_origin, [], "handshake_blocked")
                return
            if level == "session":
                _add_session_trust(req_origin)
                _send_json(self, 200, {"status": "trusted", "level": "session"}, origin)
                _audit("ALLOWED", req_origin, [], "handshake_session")
            elif level in ("graylist", "whitelist"):
                other = "whitelist" if level == "graylist" else "graylist"
                def _apply(cfg):
                    cfg[other] = [o for o in cfg[other] if o.rstrip("/") != req_origin]
                    if req_origin not in [o.rstrip("/") for o in cfg[level]]:
                        cfg[level].append(req_origin)
                _mutate_config(_apply)
                _send_json(self, 200, {"status": "trusted", "level": level}, origin)
                _audit("ALLOWED", req_origin, [], f"handshake_{level}")
            return

        # ── /agents/delete — remove a deployed script ──

        if path == "/agents/delete":
            if not self._host_ok():
                _send_json(self, 403, {"error": "invalid host"}, origin); return
            sha256 = data.get("sha256", "")
            if not sha256:
                _send_json(self, 400, {"error": "missing sha256"}, origin); return
            found = _agents_delete(sha256)
            if not found:
                _send_json(self, 404, {"error": "agent not found"}, origin); return
            _audit("DELETE", origin, [sha256[:8]], "agent_deleted")
            _send_json(self, 200, {"status": "deleted"}, origin)
            return

        # ── /setup-env — create a venv/pixi/conda env, then point config at it ──
        # The page proposes type + (name|path) + packages; the daemon confines the
        # location to $HOME, shows a native approval dialog, and runs the creation
        # as an async job. On success config["python"] points at the new env.

        if path == "/setup-env":
            classification = self._classify(origin)
            if not classification:
                _send_json(self, 403, {"error": "origin not in whitelist or graylist"}, origin)
                _audit("BLOCKED", origin or "unknown", [], "not_in_list")
                return

            env_type = data.get("type", "")
            name     = data.get("name", "")
            path_in  = data.get("path", "")
            packages = data.get("packages", [])

            if env_type not in _VALID_ENV_TYPES:
                _send_json(self, 400, {"error": f"type must be one of {list(_VALID_ENV_TYPES)}"}, origin); return
            if not isinstance(name, str) or not isinstance(path_in, str):
                _send_json(self, 400, {"error": "name and path must be strings"}, origin); return
            if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
                _send_json(self, 400, {"error": "packages must be a list of strings"}, origin); return
            bad = [p for p in packages if not _valid_pkg(p)]
            if bad:
                _send_json(self, 400, {"error": f"invalid package spec: {bad[0]!r}"}, origin); return

            try:
                target = _setup_target(name, path_in)
            except ValueError as e:
                _send_json(self, 400, {"error": str(e)}, origin); return

            base_python = sys.executable or shutil.which("python3") or "python3"
            try:
                steps, interpreter = _env_plan(env_type, target, packages, base_python)
            except ValueError as e:
                _send_json(self, 400, {"error": str(e)}, origin); return

            # Idempotent no-dialog fast path ONLY for envs this feature created
            # (under ENVS_DIR). A page-supplied `path` can point its fixed
            # "<target>/bin/python" at any pre-existing executable under $HOME, so
            # adopting that silently would let a trusted page repoint the user's
            # default python with no approval — it must go through the dialog (or
            # be refused as an existing dir below).
            # Check the env DIRECTORY (not the interpreter — a venv's bin/python
            # is a symlink to the base python, which lives outside ENVS_DIR).
            envs_root  = os.path.realpath(ENVS_DIR) + os.sep
            in_sandbox = os.path.realpath(target).startswith(envs_root)
            if _interp_ready(interpreter) and in_sandbox:
                _setup_persist_python(interpreter)
                _audit("SETUP", origin, [env_type, interpreter], "already_exists")
                _send_json(self, 200, {
                    "status": "ready", "interpreter": interpreter,
                    "target": target, "already_exists": True,
                }, origin)
                return
            # Refuse to touch an already-populated directory (includes a
            # page-supplied path that already holds an interpreter — never adopted
            # silently, never clobbered).
            if os.path.isdir(target) and os.listdir(target):
                _send_json(self, 400, {
                    "error": f"target already exists: {target}"
                }, origin); return

            approved = _request_setup_approval(origin, env_type, target, packages, steps)
            if not approved:
                _send_json(self, 403, {"error": "env setup denied by user"}, origin)
                _audit("DENIED", origin, [env_type, target], "setup_denied_by_user")
                return

            job = _setup_start(env_type, target, packages, interpreter, steps, origin)
            _audit("APPROVED", origin, [env_type, target], "setup_started")
            _send_json(self, 200, {
                "status":      "running",
                "job_id":      job["id"],
                "log_path":    job["log_path"],
                "target":      target,
                "interpreter": interpreter,   # where it WILL be once the job finishes
            }, origin)
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

            cmd_list = _resolve_interpreter([command] + args)
            preview  = _read_script_preview(cmd_list)

            if classification == "graylist":
                approved = _request_approval(origin, ["[spawn]"] + cmd_list, preview)
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

        # ── /deploy — verify SHA-256, write file, spawn ──────────────────────
        # Always shows the approval dialog regardless of whitelist/graylist,
        # because writing executable code to disk is more powerful than running
        # a known command. The dialog shows filename, full SHA-256, destination,
        # and the exact command so the user can verify before approving.

        if path == "/deploy":
            classification = self._classify(origin)
            if not classification:
                _send_json(self, 403, {"error": "origin not in whitelist or graylist"}, origin)
                _audit("BLOCKED", origin or "unknown", [], "not_in_list")
                return

            source   = data.get("source",   "")
            sha256   = data.get("sha256",   "")
            filename = data.get("filename", "agent.py")
            command  = data.get("command",  "")
            args     = data.get("args",     [])

            if not isinstance(source, str) or not source:
                _send_json(self, 400, {"error": "source must be a non-empty string"}, origin); return
            if len(source.encode("utf-8")) > 1 * 1024 * 1024:
                _send_json(self, 400, {"error": "source exceeds 1 MB limit"}, origin); return
            if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
                _send_json(self, 400, {"error": "sha256 must be a 64-char hex string"}, origin); return
            if not command or not isinstance(command, str):
                _send_json(self, 400, {"error": "command must be a non-empty string"}, origin); return
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                _send_json(self, 400, {"error": "args must be a list of strings"}, origin); return

            # Verify hash before asking user — no point showing the dialog for
            # a tampered payload.
            actual_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
            if actual_hash != sha256.lower():
                _send_json(self, 400, {
                    "error": f"SHA-256 mismatch: provided {sha256[:8]}…, content is {actual_hash[:8]}…"
                }, origin)
                _audit("BLOCKED", origin, [filename], "sha256_mismatch")
                return

            dest_path = _deploy_resolve(filename, sha256)
            cmd_list  = _resolve_interpreter([command, dest_path] + args)

            # Check if already running — re-runnable without a second dialog.
            live     = _proc_list_live()
            existing = next(
                (e for e in live
                 if len(e["command"]) >= 2 and e["command"][1] == dest_path),
                None
            )
            if existing:
                _send_json(self, 200, {
                    "pid":            existing["pid"],
                    "path":           dest_path,
                    "started_at":     existing["started_at"],
                    "log_path":       existing["log_path"],
                    "already_running": True,
                }, origin)
                _audit("SKIP", origin, cmd_list, f"already_running_pid:{existing['pid']}")
                return

            # Always show the deploy dialog — whitelist or graylist.
            approved = _request_deploy_approval(origin, filename, sha256, dest_path, cmd_list, source)
            if not approved:
                _send_json(self, 403, {"error": "deploy denied by user"}, origin)
                _audit("DENIED", origin, [filename, sha256[:8]], "deploy_denied_by_user")
                return

            # Write file (idempotent if same hash already on disk).
            try:
                dest_path, was_written = _deploy_write(source, sha256, filename)
            except ValueError as e:
                _send_json(self, 400, {"error": str(e)}, origin); return

            if was_written:
                _audit("WRITE", origin, [dest_path, sha256[:8]], "file_written")
            else:
                _audit("WRITE", origin, [dest_path, sha256[:8]], "file_cached")
            _agents_record(sha256, filename, dest_path, origin)

            # Spawn.
            try:
                entry = _proc_spawn(cmd_list, origin)
                _audit("APPROVED", origin, cmd_list, "deploy_spawned")
                _send_json(self, 200, {
                    "pid":        entry["pid"],
                    "path":       dest_path,
                    "started_at": entry["started_at"],
                    "log_path":   entry["log_path"],
                }, origin)
            except FileNotFoundError:
                _send_json(self, 400, {"error": f"command not found: {command}"}, origin)
                _audit("ERROR", origin, cmd_list, "deploy_command_not_found")
            except OSError as e:
                _send_json(self, 500, {"error": f"spawn failed: {e}"}, origin)
                _audit("ERROR", origin, cmd_list, f"deploy_oserror:{e}")
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

            cmd_list = _resolve_interpreter([command] + args)
            preview  = _read_script_preview(cmd_list)

            if classification == "graylist":
                approved = _request_approval(origin, cmd_list, preview)
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
