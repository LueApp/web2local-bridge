#!/usr/bin/env python3
"""Unit tests for /env/select path resolution (_looks_like_python, _resolve_select_path).

Run with any python3:  python3 test_env_select_endpoint.py
"""
import importlib.util
import os
import shutil
import stat
import sys
import tempfile

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

def check_raises(name, fn, needle=None):
    try:
        fn()
    except ValueError as e:
        if needle and needle not in str(e):
            print(f"FAIL  {name}: message {str(e)!r} lacks {needle!r}"); _failures.append(name)
        else:
            print(f"  ok  {name}")
    except Exception as e:
        print(f"FAIL  {name}: raised {type(e).__name__}"); _failures.append(name)
    else:
        print(f"FAIL  {name}: did not raise"); _failures.append(name)

HOME = os.path.realpath(os.path.expanduser("~"))

def make_exe(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("#!/bin/sh\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path

# ── _looks_like_python ───────────────────────────────────────────────────────
print("_looks_like_python")
for ok in ["python", "python3", "python2", "python3.11", "python3.12",
           "pythonw", "PYTHON3", "/a/b/python", "python.exe", "python3.12.exe"]:
    check(f"  accepts {ok!r}", d._looks_like_python(ok), True)
for bad in ["bash", "ls", "node", "ipython", "sh", "pythonista", "py3", "snake"]:
    check(f"  rejects {bad!r}", d._looks_like_python(bad), False)

# ── _resolve_select_path ─────────────────────────────────────────────────────
print("_resolve_select_path")
# Work inside a temp dir UNDER $HOME so confinement passes.
work = tempfile.mkdtemp(dir=HOME, prefix=".w2l-sel-")
try:
    # venv-style prefix → bin/python
    prefix = os.path.join(work, ".venv")
    py = make_exe(os.path.join(prefix, "bin", "python"))
    check("  prefix -> bin/python", d._resolve_select_path(prefix), py)

    # conda-style prefix with only bin/python3
    cprefix = os.path.join(work, "envs", "foo")
    py3 = make_exe(os.path.join(cprefix, "bin", "python3"))
    check("  prefix -> bin/python3 fallback", d._resolve_select_path(cprefix), py3)

    # explicit executable
    check("  executable path accepted", d._resolve_select_path(py), py)

    # ~ expansion: build a path expressed with ~
    rel = os.path.relpath(prefix, HOME)
    check("  ~ expansion", d._resolve_select_path(os.path.join("~", rel)), py)

    # errors
    check_raises("  nonexistent path", lambda: d._resolve_select_path(os.path.join(work, "nope")),
                 "does not exist")
    check_raises("  outside $HOME", lambda: d._resolve_select_path("/etc"),
                 "inside your home")
    emptydir = os.path.join(work, "emptyenv"); os.makedirs(emptydir)
    check_raises("  prefix without python", lambda: d._resolve_select_path(emptydir),
                 "no python interpreter")
    notpy = make_exe(os.path.join(work, "bin", "bash"))
    check_raises("  non-python executable", lambda: d._resolve_select_path(notpy),
                 "does not look like a python")
    nonexec = os.path.join(work, "bin", "python_textfile")
    with open(nonexec, "w") as f: f.write("x")   # named python-ish but not executable
    # rename to a python-looking name that's not executable
    pyne = os.path.join(work, "bin", "python")  # already exists+exec from earlier? that's under .venv
    plain = os.path.join(work, "plainpython"); open(plain, "w").write("x")  # not executable
    check_raises("  non-executable file", lambda: d._resolve_select_path(plain),
                 "not an executable")
    check_raises("  empty path", lambda: d._resolve_select_path("   "), "required")

    # ── symlink target validation (consent integrity) ──
    # A file named "python" that symlinks to a NON-python binary must be rejected.
    evilbin = os.path.join(work, "evil", "bin"); os.makedirs(evilbin)
    badlink = os.path.join(evilbin, "python")
    os.symlink("/bin/sh", badlink)
    check_raises("  symlink → non-python rejected",
                 lambda: d._resolve_select_path(badlink), "non-python target")
    # A venv-style symlink → a python-named target is accepted.
    target = make_exe(os.path.join(work, "real", "python3.11"))
    glinkd = os.path.join(work, "venv2", "bin"); os.makedirs(glinkd)
    goodlink = os.path.join(glinkd, "python")
    os.symlink(target, goodlink)
    check("  symlink → python-named target accepted",
          d._resolve_select_path(goodlink), goodlink)
finally:
    shutil.rmtree(work, ignore_errors=True)

print()
if _failures:
    print(f"{len(_failures)} FAILED: {_failures}"); sys.exit(1)
print("ALL PASSED")
