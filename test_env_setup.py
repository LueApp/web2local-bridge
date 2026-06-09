#!/usr/bin/env python3
"""Unit tests for daemon.py's python-environment provisioning (/setup-env).

Run with any python3:  python3 test_env_setup.py
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("w2l_daemon", os.path.join(HERE, "daemon.py"))
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)

_failures = []
def check(name, got, want):
    if got == want:
        print(f"  ok  {name}")
    else:
        print(f"FAIL  {name}\n        got : {got!r}\n        want: {want!r}")
        _failures.append(name)

def check_raises(name, fn):
    try:
        fn()
    except ValueError:
        print(f"  ok  {name}")
    except Exception as e:
        print(f"FAIL  {name}: raised {type(e).__name__} not ValueError"); _failures.append(name)
    else:
        print(f"FAIL  {name}: did not raise"); _failures.append(name)

HOME = os.path.realpath(os.path.expanduser("~"))

# ── _valid_pkg ──────────────────────────────────────────────────────────────────
print("_valid_pkg")
for ok in ["numpy", "requests==2.31.*", "pandas>=1.0", "pkg[extra]", "a.b-c_1", "ruamel.yaml"]:
    check(f"  accepts {ok!r}", d._valid_pkg(ok), True)
# Note: < > = ! ~ , * [ ] are allowed (PEP 440 specifiers, e.g. numpy>=1.0); since
# everything runs via argv (no shell) they are literal, not metacharacters.
for bad in ["", "--index-url=http://x", "-r", "a b", "a;b", "a&&b", "$(x)", "/etc/passwd",
            "a|b", "`x`", "a/b", "..", "a'b", "a\\b", "a{b}"]:
    check(f"  rejects {bad!r}", d._valid_pkg(bad), False)

# ── _setup_target ───────────────────────────────────────────────────────────────
print("_setup_target")
check("  name -> ENVS_DIR", d._setup_target("myapp", ""), os.path.join(d.ENVS_DIR, "myapp"))
# Traversal via name is flattened, never escapes ENVS_DIR.
tv = d._setup_target("../../etc/x", "")
check("  traversal name flattened", tv, os.path.join(d.ENVS_DIR, "etc_x"))
check("  traversal stays under ENVS_DIR", tv.startswith(d.ENVS_DIR + os.sep), True)
# Explicit path inside home is accepted.
inside = os.path.join(HOME, "code", "proj", ".venv")
check("  path inside home", d._setup_target("", inside), os.path.realpath(inside))
# Path outside home / at home / empty are rejected.
check_raises("  path outside home rejected", lambda: d._setup_target("", "/tmp/evil-env"))
check_raises("  path == home rejected", lambda: d._setup_target("", "~"))
check_raises("  neither name nor path", lambda: d._setup_target("", ""))
check_raises("  blank name rejected", lambda: d._setup_target("...", ""))

# ── _env_plan ───────────────────────────────────────────────────────────────────
print("_env_plan")
T = os.path.join(HOME, ".cache", "w2l-test-env")
steps, interp = d._env_plan("venv", T, [], "/usr/bin/python3")
check("  venv steps (no pkgs)", steps, [["/usr/bin/python3", "-m", "venv", T]])
check("  venv interp", interp, os.path.join(T, "bin", "python"))
steps, interp = d._env_plan("venv", T, ["flask", "requests"], "/usr/bin/python3")
check("  venv adds pip install", steps[1],
      [os.path.join(T, "bin", "python"), "-m", "pip", "install", "flask", "requests"])

# pixi is installed in this environment.
pixi = shutil.which("pixi")
if pixi:
    steps, interp = d._env_plan("pixi", T, ["numpy"], "/usr/bin/python3")
    check("  pixi init step", steps[0], [pixi, "init", T])
    check("  pixi add step", steps[1],
          [pixi, "add", "--manifest-path", os.path.join(T, "pixi.toml"), "python", "numpy"])
    check("  pixi interp path", interp,
          os.path.join(T, ".pixi", "envs", "default", "bin", "python"))
else:
    check_raises("  pixi missing -> ValueError", lambda: d._env_plan("pixi", T, [], "x"))

# conda is NOT installed in this environment.
if d._conda_exe():
    conda = d._conda_exe()
    steps, interp = d._env_plan("conda", T, ["numpy"], "x")
    check("  conda create step", steps[0], [conda, "create", "-y", "-p", T, "python", "numpy"])
    check("  conda interp", interp, os.path.join(T, "bin", "python"))
else:
    check_raises("  conda missing -> ValueError", lambda: d._env_plan("conda", T, [], "x"))

check_raises("  unknown type -> ValueError", lambda: d._env_plan("poetry", T, [], "x"))

# ── _interp_ready ────────────────────────────────────────────────────────────────
print("_interp_ready")
check("  missing -> False", d._interp_ready("/no/such/python"), False)
check("  empty -> False", d._interp_ready(""), False)
check("  real python -> True", d._interp_ready(sys.executable), True)

# ── worker: success sets config["python"], failure does not ──────────────────────
print("_setup_worker (via _setup_start)")
_orig = {k: getattr(d, k) for k in ("CONFIG_DIR", "CONFIG_PATH", "LOG_PATH", "PROC_DIR", "PROC_INDEX", "ENVS_DIR")}
tmp = tempfile.mkdtemp(prefix="w2l-setup-")
d.CONFIG_DIR = tmp
d.CONFIG_PATH = os.path.join(tmp, "config.json")
d.LOG_PATH    = os.path.join(tmp, "audit.log")
d.PROC_DIR    = os.path.join(tmp, "proc")
d.PROC_INDEX  = os.path.join(tmp, "proc.json")
d.ENVS_DIR    = os.path.join(tmp, "envs")
try:
    d._update_config({"port": 0, "whitelist": [], "graylist": [], "python": ""})

    def wait_job(jid, timeout=20):
        for _ in range(int(timeout / 0.1)):
            with d._setup_lock:
                st = d._setup_jobs[jid]["status"]
            if st in ("done", "failed"):
                return st
            time.sleep(0.1)
        return "timeout"

    # Success: a step that creates the target interpreter file.
    target = os.path.join(tmp, "envs", "ok")
    interp = os.path.join(target, "bin", "python")
    mk = [sys.executable, "-c",
          "import os,stat;"
          f"os.makedirs({os.path.dirname(interp)!r},exist_ok=True);"
          f"open({interp!r},'w').write('#!/bin/sh\\n');"
          f"os.chmod({interp!r},0o755)"]
    job = d._setup_start("venv", target, [], interp, [mk], "http://site")
    check("  success status done", wait_job(job["id"]), "done")
    check("  config['python'] set in memory", d._get_config().get("python"), interp)
    check("  config persisted to disk", json.load(open(d.CONFIG_PATH)).get("python"), interp)
    check("  job records interpreter", d._setup_jobs[job["id"]]["interpreter"], interp)

    # Failure: reset config, run a step that exits nonzero -> config must stay "".
    d._update_config({"port": 0, "whitelist": [], "graylist": [], "python": ""})
    fail = [sys.executable, "-c", "import sys; sys.exit(3)"]
    bad_interp = os.path.join(tmp, "envs", "bad", "bin", "python")
    job2 = d._setup_start("venv", os.path.join(tmp, "envs", "bad"), [], bad_interp, [fail], "http://site")
    check("  failure status failed", wait_job(job2["id"]), "failed")
    check("  config['python'] unchanged on failure", d._get_config().get("python"), "")

    # Success-but-interpreter-missing: steps succeed yet interp absent -> failed.
    job3 = d._setup_start("venv", os.path.join(tmp, "envs", "ghost"),
                          [], os.path.join(tmp, "envs", "ghost", "bin", "python"),
                          [[sys.executable, "-c", "pass"]], "http://site")
    check("  missing-interp -> failed", wait_job(job3["id"]), "failed")

    # ── config atomicity: concurrent writers don't lose updates ──
    print("config atomicity (_mutate_config)")
    import threading as _th
    d._update_config({"port": 0, "whitelist": [], "graylist": [], "python": ""})
    def _add(i):
        d._mutate_config(lambda c: c["whitelist"].append(f"http://s{i}"))
    threads = [_th.Thread(target=_add, args=(i,)) for i in range(25)]
    for t in threads: t.start()
    for t in threads: t.join()
    check("  25 concurrent appends all survive", len(set(d._get_config()["whitelist"])), 25)
    # Interleave list appends with python-key writes (the worker's path).
    d._update_config({"port": 0, "whitelist": [], "graylist": [], "python": ""})
    def _mixed(i):
        if i % 2 == 0:
            d._mutate_config(lambda c: c["whitelist"].append(f"http://m{i}"))
        else:
            d._setup_persist_python(f"/p/{i}/bin/python")
    t2 = [_th.Thread(target=_mixed, args=(i,)) for i in range(20)]
    for t in t2: t.start()
    for t in t2: t.join()
    cfg = d._get_config()
    check("  whitelist intact under interleaved python writes", len(cfg["whitelist"]), 10)
    check("  python set by one of the writers", cfg["python"].startswith("/p/"), True)
    check("  on-disk config.json parses", isinstance(json.load(open(d.CONFIG_PATH)), dict), True)

    # ── _load_config survives a corrupt file ──
    print("_load_config corruption tolerance")
    with open(d.CONFIG_PATH, "w") as f:
        f.write("{ not valid json ]")
    d._load_config()  # must NOT raise
    check("  corrupt config -> defaults, no crash", d._get_config().get("whitelist"), [])

    # ── per-target dedup: 2nd start for an in-flight target returns the 1st job ──
    print("per-target dedup")
    slow = [sys.executable, "-c", "import time; time.sleep(2)"]
    tgt  = os.path.join(tmp, "envs", "dedup")
    di   = os.path.join(tgt, "bin", "python")
    j1 = d._setup_start("venv", tgt, [], di, [slow], "http://s")
    j2 = d._setup_start("venv", tgt, [], di, [slow], "http://s")
    check("  same job id for an in-flight target", j2["id"], j1["id"])
    wait_job(j1["id"], timeout=10)
finally:
    for k, v in _orig.items():
        setattr(d, k, v)
    shutil.rmtree(tmp, ignore_errors=True)

print()
if _failures:
    print(f"{len(_failures)} FAILED: {_failures}"); sys.exit(1)
print("ALL PASSED")
