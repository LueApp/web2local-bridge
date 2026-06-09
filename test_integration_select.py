#!/usr/bin/env python3
"""Live HTTP integration test for POST /env/select (and the CORS-preflight + deploy
resolution requirements from the can-codec contract). Uses a temp config dir and a
thread that auto-approves the native dialog."""
import http.client
import importlib.util
import json
import os
import queue
import stat
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("w2l_daemon", os.path.join(HERE, "daemon.py"))
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)

failures = []
def check(name, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if not ok:
        print(f"        got : {got!r}\n        want: {want!r}")
        failures.append(name)

tmp = tempfile.mkdtemp(prefix="w2l-select-itest-")
d.CONFIG_DIR  = tmp
d.CONFIG_PATH = os.path.join(tmp, "config.json")
d.LOG_PATH    = os.path.join(tmp, "audit.log")
d.PROC_DIR    = os.path.join(tmp, "processes")
d.PROC_INDEX  = os.path.join(tmp, "processes.json")
d.ENVS_DIR    = os.path.join(tmp, "envs")
d.os.environ["HOME"] = tmp   # confine $HOME to the temp dir

ORIGIN = "http://localhost:7171"
d._update_config({"port": 0, "whitelist": [ORIGIN], "graylist": [], "python": ""})

def make_venv(prefix):
    py = os.path.join(prefix, "bin", "python")
    os.makedirs(os.path.dirname(py), exist_ok=True)
    with open(py, "w") as f: f.write("#!/bin/sh\n")
    os.chmod(py, os.stat(py).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return prefix, py

prefix1, py1 = make_venv(os.path.join(tmp, "proj", ".venv"))
prefix2, py2 = make_venv(os.path.join(tmp, "proj2", ".venv"))

# Auto-approve any dialog (stands in for the user).
_stop = threading.Event()
def _approver():
    while not _stop.is_set():
        try:
            item = d._dialog_queue.get(timeout=0.2)
        except queue.Empty:
            continue
        item[3][0] = True  # result
        item[2].set()      # event
threading.Thread(target=_approver, daemon=True).start()

srv = ThreadingHTTPServer(("127.0.0.1", 0), d.Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

def req(method, path, body=None, origin=ORIGIN):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {"Host": "127.0.0.1"}
    if origin: headers["Origin"] = origin
    payload = None
    if body is not None:
        headers["Content-Type"] = "application/json"; payload = json.dumps(body)
    c.request(method, path, payload, headers)
    r = c.getresponse()
    raw = r.read()
    hdrs = dict(r.getheaders())
    c.close()
    data = {}
    if raw:
        try: data = json.loads(raw)
        except Exception: data = {}
    return r.status, data, hdrs

try:
    print("select by env prefix")
    st, data, _ = req("POST", "/env/select", {"path": prefix1})
    check("  status 200", st, 200)
    check("  status selected", data.get("status"), "selected")
    check("  interpreter resolved to bin/python", data.get("interpreter"), py1)
    check("  source config", data.get("source"), "config")
    check("  config_python == interpreter", data.get("config_python"), py1)
    check("  already_selected false", data.get("already_selected"), False)

    st, envd, _ = req("GET", "/env")
    check("  /env reflects selection", envd.get("interpreter"), py1)
    check("  /env source config", envd.get("source"), "config")

    print("deploy-resolution: bare python3 now maps to the selected interpreter")
    check("  _resolve_interpreter(python3, x.py) -> selected",
          d._resolve_interpreter(["python3", "/some/x.py"]), [py1, "/some/x.py"])

    print("idempotent re-select (no dialog, already_selected)")
    st, data, _ = req("POST", "/env/select", {"path": prefix1})
    check("  already_selected true", data.get("already_selected"), True)
    check("  interpreter unchanged", data.get("interpreter"), py1)

    print("select by python executable path")
    st, data, _ = req("POST", "/env/select", {"path": py2})
    check("  exe path selected", data.get("status"), "selected")
    check("  interpreter == exe", data.get("interpreter"), py2)
    check("  switched away from py1", data.get("already_selected"), False)

    print("negative cases")
    st, _, _ = req("POST", "/env/select", {"path": prefix1}, origin="http://evil.example")
    check("  untrusted origin -> 403", st, 403)
    st, _, _ = req("POST", "/env/select", {"path": "/etc"})
    check("  outside $HOME -> 400", st, 400)
    st, _, _ = req("POST", "/env/select", {"path": os.path.join(tmp, "nope")})
    check("  nonexistent -> 400", st, 400)
    st, _, _ = req("POST", "/env/select", {"path": ""})
    check("  empty path -> 400", st, 400)

    print("CORS preflight for /env/select and /setup-env")
    for ep in ("/env/select", "/setup-env"):
        st, _, hdrs = req("OPTIONS", ep)
        check(f"  OPTIONS {ep} (trusted) -> 204", st, 204)
        check(f"  OPTIONS {ep} reflects origin", hdrs.get("Access-Control-Allow-Origin"), ORIGIN)
        st, _, _ = req("OPTIONS", ep, origin="http://evil.example")
        check(f"  OPTIONS {ep} (untrusted) -> 403", st, 403)

    print("hardening regressions")
    # Non-object JSON body must yield a clean 400, not a 500/traceback.
    st, _, _ = req("POST", "/env/select", [])
    check("  array body -> clean 400", st, 400)
    # config stored as an env PREFIX is still recognised when selecting its exe.
    d._update_config({**d._get_config(), "python": prefix1})
    st, data, _ = req("POST", "/env/select", {"path": py1})
    check("  prefix-form config -> already_selected", data.get("already_selected"), True)
finally:
    _stop.set()
    srv.shutdown()

print()
if failures:
    print(f"{len(failures)} FAILED: {failures}"); sys.exit(1)
print("ALL PASSED")
