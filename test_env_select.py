#!/usr/bin/env python3
"""Unit tests for daemon.py's python-environment selection.

Run with any python3:  python3 test_env_select.py
(If you use pixi/conda/venv, run it with that interpreter — the tests don't
depend on it, but it keeps everything in one environment.)
"""
import importlib.util
import os
import stat
import sys
import tempfile

# Import the daemon module by path (it guards main() behind __main__).
_spec = importlib.util.spec_from_file_location(
    "w2l_daemon", os.path.join(os.path.dirname(os.path.abspath(__file__)), "daemon.py"))
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)

_failures = []


def check(name, got, want):
    if got == want:
        print(f"  ok  {name}")
    else:
        print(f"FAIL  {name}\n        got : {got!r}\n        want: {want!r}")
        _failures.append(name)


def make_exe(path):
    """Create an executable stub file at path (and parent dirs)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("#!/bin/sh\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def make_prefix(root, name):
    """Create an env prefix dir <root>/<name> with bin/python + bin/python3."""
    prefix = os.path.join(root, name)
    if os.name == "nt":
        make_exe(os.path.join(prefix, "python.exe"))
    else:
        make_exe(os.path.join(prefix, "bin", "python"))
        make_exe(os.path.join(prefix, "bin", "python3"))
    return prefix


# Capture & restore mutable global state we poke at.
_orig_config = d._get_config()
_orig_environ = dict(os.environ)


def set_config_python(value):
    cfg = d._get_config()
    cfg["python"] = value
    d._update_config(cfg)


def reset_state():
    d._update_config(dict(_orig_config))
    os.environ.clear()
    os.environ.update(_orig_environ)
    os.environ.pop("VIRTUAL_ENV", None)
    os.environ.pop("CONDA_PREFIX", None)


# ── _is_python_command ─────────────────────────────────────────────────────────
print("_is_python_command")
for name in ["python", "python3", "python2",
             "python3.11", "python3.12", "python2.7", "python3.13t", "PYTHON3"]:
    check(f"  recognises {name}", d._is_python_command(name), True)
# "py" (Windows launcher) and "pythonw" (windowless) are intentionally NOT
# rewritten — they pass through to PATH / the launcher unchanged.
for name in ["", "bash", "node", "ls", "pythonista", "ipython",
             "/usr/bin/python3", "./python", "envpython", "python3x",
             "py", "pythonw"]:
    check(f"  rejects {name!r}", d._is_python_command(name), False)

# ── _script_arg: pick the real script, never a flag ─────────────────────────────
print("_script_arg")
check("  plain script", d._script_arg(["s.py", "a", "b"]), "s.py")
check("  -c => no script", d._script_arg(["-c", "print(1)"]), None)
check("  -m => no script", d._script_arg(["-m", "http.server"]), None)
check("  glued -mmod => no script", d._script_arg(["-mhttp.server", "x.py"]), None)
check("  glued -cCODE => no script", d._script_arg(["-cprint(1)"]), None)
check("  bare - (stdin) => no script", d._script_arg(["-"]), None)
check("  -u flag then script", d._script_arg(["-u", "s.py"]), "s.py")
check("  -OO bundled flag then script", d._script_arg(["-OO", "s.py"]), "s.py")
check("  -W value then script", d._script_arg(["-W", "ignore", "s.py"]), "s.py")
check("  -X value then script", d._script_arg(["-X", "faulthandler", "s.py"]), "s.py")
check("  only flags => None", d._script_arg(["-u", "-O"]), None)
check("  empty => None", d._script_arg([]), None)

# ── _python_exe_for_prefix ─────────────────────────────────────────────────────
print("_python_exe_for_prefix")
with tempfile.TemporaryDirectory() as tmp:
    prefix = make_prefix(tmp, "envA")
    exp = os.path.join(prefix, "python.exe") if os.name == "nt" else os.path.join(prefix, "bin", "python")
    check("  finds bin/python in prefix", d._python_exe_for_prefix(prefix), exp)
    check("  None for empty dir", d._python_exe_for_prefix(os.path.join(tmp, "nope")), None)

# ── _interp_from_hint ──────────────────────────────────────────────────────────
print("_interp_from_hint")
with tempfile.TemporaryDirectory() as tmp:
    prefix = make_prefix(tmp, "envH")
    direct = os.path.join(prefix, "python.exe") if os.name == "nt" else os.path.join(prefix, "bin", "python")
    check("  direct interpreter path", d._interp_from_hint(direct), direct)
    check("  env prefix directory", d._interp_from_hint(prefix), direct)
    check("  ~ is expanded (nonexistent → None)",
          d._interp_from_hint("~/definitely-not-a-real-python-xyz"), None)
    # Bare name on PATH should resolve via shutil.which (use the running python).
    import shutil
    real = shutil.which("python3") or shutil.which("python")
    if real:
        check("  bare name via PATH", bool(d._interp_from_hint(os.path.basename(real))), True)

# ── _find_project_python: venv discovery + walk-up ─────────────────────────────
print("_find_project_python")
with tempfile.TemporaryDirectory() as tmp:
    proj = os.path.join(tmp, "proj")
    sub = os.path.join(proj, "a", "b")
    os.makedirs(sub, exist_ok=True)
    venv_py = d._python_exe_for_prefix(make_prefix(proj, ".venv"))
    script = os.path.join(sub, "run.py")
    open(script, "w").close()
    check("  finds .venv walking up from nested script",
          d._find_project_python(script), venv_py)

with tempfile.TemporaryDirectory() as tmp:
    proj = os.path.join(tmp, "proj")
    os.makedirs(proj, exist_ok=True)
    # pixi layout: .pixi/envs/default/bin/python
    pixi_default = d._python_exe_for_prefix(make_prefix(os.path.join(proj, ".pixi", "envs"), "default"))
    script = os.path.join(proj, "x.py")
    open(script, "w").close()
    check("  finds .pixi/envs/default", d._find_project_python(script), pixi_default)

with tempfile.TemporaryDirectory() as tmp:
    proj = os.path.join(tmp, "proj")
    os.makedirs(proj, exist_ok=True)
    # pixi with only a non-default env name
    pixi_ml = d._python_exe_for_prefix(make_prefix(os.path.join(proj, ".pixi", "envs"), "ml"))
    script = os.path.join(proj, "x.py")
    open(script, "w").close()
    check("  finds single non-default pixi env", d._find_project_python(script), pixi_ml)

with tempfile.TemporaryDirectory() as tmp:
    script = os.path.join(tmp, "lonely.py")
    open(script, "w").close()
    check("  None when no env nearby", d._find_project_python(script), None)

with tempfile.TemporaryDirectory() as tmp:
    # Security: a world-writable project dir is untrusted — a local attacker
    # could plant a .venv there. Discovery must skip it.
    proj = os.path.join(tmp, "wwproj")
    os.makedirs(proj, exist_ok=True)
    venv_py = d._python_exe_for_prefix(make_prefix(proj, ".venv"))
    script = os.path.join(proj, "x.py"); open(script, "w").close()
    if hasattr(os, "geteuid"):
        os.chmod(proj, 0o777)
        check("  world-writable dir rejected", d._find_project_python(script), None)
        os.chmod(proj, 0o755)
        check("  same dir at 0o755 accepted", d._find_project_python(script), venv_py)
    else:
        print("  skip  world-writable test (no POSIX uid)")

# ── _path_is_trusted ────────────────────────────────────────────────────────────
print("_path_is_trusted")
with tempfile.TemporaryDirectory() as tmp:
    if hasattr(os, "geteuid"):
        good = os.path.join(tmp, "good"); os.makedirs(good); os.chmod(good, 0o755)
        check("  owned + not world-writable", d._path_is_trusted(good), True)
        gw = os.path.join(tmp, "gw"); os.makedirs(gw); os.chmod(gw, 0o775)
        check("  group-writable tolerated (umask 0002)", d._path_is_trusted(gw), True)
        ww = os.path.join(tmp, "ww"); os.makedirs(ww); os.chmod(ww, 0o777)
        check("  world-writable rejected", d._path_is_trusted(ww), False)
        check("  missing path rejected", d._path_is_trusted(os.path.join(tmp, "nope")), False)
    else:
        print("  skip (no POSIX uid)")

# ── _find_active_python: env vars ──────────────────────────────────────────────
print("_find_active_python")
with tempfile.TemporaryDirectory() as tmp:
    reset_state()
    venv = make_prefix(tmp, "active_venv")
    venv_py = d._python_exe_for_prefix(venv)
    os.environ["VIRTUAL_ENV"] = venv
    check("  picks up VIRTUAL_ENV", d._find_active_python(), venv_py)
    reset_state()
    conda = make_prefix(tmp, "active_conda")
    conda_py = d._python_exe_for_prefix(conda)
    os.environ["CONDA_PREFIX"] = conda
    check("  picks up CONDA_PREFIX (pixi/conda)", d._find_active_python(), conda_py)
    reset_state()
    check("  None when no env active", d._find_active_python(), None)

# ── _detect_python: priority order ─────────────────────────────────────────────
print("_detect_python priority")
with tempfile.TemporaryDirectory() as tmp:
    reset_state()
    cfg_prefix = make_prefix(tmp, "cfgenv")
    cfg_py = d._python_exe_for_prefix(cfg_prefix)
    proj = os.path.join(tmp, "proj"); os.makedirs(proj, exist_ok=True)
    proj_py = d._python_exe_for_prefix(make_prefix(proj, ".venv"))
    active = make_prefix(tmp, "activeenv")
    os.environ["VIRTUAL_ENV"] = active
    script = os.path.join(proj, "s.py"); open(script, "w").close()

    set_config_python(cfg_prefix)
    check("  config beats project & active", d._detect_python(script), (cfg_py, "config"))

    set_config_python("")
    check("  project beats active", d._detect_python(script), (proj_py, "project"))

    # No script path → skip project tier, fall to active env.
    active_py = d._python_exe_for_prefix(active)
    check("  active-env when no script", d._detect_python(None), (active_py, "active-env"))

    reset_state()
    check("  path fallback when nothing set", d._detect_python(None), (None, "path"))

# ── _resolve_interpreter: end-to-end rewrite ───────────────────────────────────
print("_resolve_interpreter")
with tempfile.TemporaryDirectory() as tmp:
    reset_state()
    cfg_prefix = make_prefix(tmp, "rese")
    cfg_py = d._python_exe_for_prefix(cfg_prefix)
    set_config_python(cfg_prefix)
    check("  rewrites python3 → configured interpreter",
          d._resolve_interpreter(["python3", "/some/x.py", "--flag"]),
          [cfg_py, "/some/x.py", "--flag"])
    check("  rewrites versioned python3.12",
          d._resolve_interpreter(["python3.12", "x.py"]), [cfg_py, "x.py"])
    # Non-python commands untouched.
    check("  leaves non-python command alone",
          d._resolve_interpreter(["ls", "-la"]), ["ls", "-la"])
    check("  leaves bash script alone",
          d._resolve_interpreter(["bash", "deploy.sh"]), ["bash", "deploy.sh"])
    # Explicit interpreter path untouched (page can't be remapped, user already approves).
    check("  leaves explicit interpreter path alone",
          d._resolve_interpreter(["/usr/bin/python3", "x.py"]), ["/usr/bin/python3", "x.py"])
    # Windows launcher / windowless interpreter are never rewritten.
    check("  leaves 'pythonw' alone",
          d._resolve_interpreter(["pythonw", "x.pyw"]), ["pythonw", "x.pyw"])
    check("  leaves 'py' launcher alone",
          d._resolve_interpreter(["py", "-3.11", "x.py"]), ["py", "-3.11", "x.py"])
    reset_state()
    # Nothing configured/detected → unchanged.
    check("  unchanged when nothing resolves",
          d._resolve_interpreter(["python3", "x.py"]), ["python3", "x.py"])
    check("  empty list safe", d._resolve_interpreter([]), [])

# Flag invocations (-c/-m) must not anchor project discovery on the daemon's CWD.
print("_resolve_interpreter: -c/-m don't pick project env from CWD")
with tempfile.TemporaryDirectory() as tmp:
    reset_state()
    proj = os.path.join(tmp, "cwdproj"); os.makedirs(proj); os.chmod(proj, 0o755)
    venv_py = d._python_exe_for_prefix(make_prefix(proj, ".venv"))
    open(os.path.join(proj, "s.py"), "w").close()
    cwd0 = os.getcwd()
    try:
        os.chdir(proj)
        check("  'python3 s.py' uses project venv (relative path)",
              d._resolve_interpreter(["python3", "s.py"]), [venv_py, "s.py"])
        check("  'python3 -c …' stays unchanged",
              d._resolve_interpreter(["python3", "-c", "print(1)"]),
              ["python3", "-c", "print(1)"])
        check("  'python3 -m …' stays unchanged",
              d._resolve_interpreter(["python3", "-m", "http.server"]),
              ["python3", "-m", "http.server"])
    finally:
        os.chdir(cwd0)

# A non-string config["python"] (hand-edit typo) must never crash the hot path.
print("non-string config['python'] is safe")
for bad in [123, ["python3"], {}, True]:
    reset_state()
    cfg = d._get_config(); cfg["python"] = bad; d._update_config(cfg)
    try:
        check(f"  _detect_python tolerates {bad!r}", d._detect_python(None), (None, "path"))
    except Exception as e:
        check(f"  _detect_python tolerates {bad!r}", f"RAISED {type(e).__name__}", "no exception")

reset_state()
print()
if _failures:
    print(f"{len(_failures)} FAILED: {_failures}")
    sys.exit(1)
print("ALL PASSED")
