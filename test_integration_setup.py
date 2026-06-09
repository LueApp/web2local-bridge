#!/usr/bin/env python3
"""Live HTTP integration test for /setup-env: actually creates a venv through the
real Handler, with a thread that auto-approves the native dialog. Uses a temp
config dir so it never touches the user's ~/.config/web2local."""
import http.client
import importlib.util
import json
import os
import queue
import sys
import tempfile
import threading
import time
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

tmp = tempfile.mkdtemp(prefix="w2l-setup-itest-")
d.CONFIG_DIR  = tmp
d.CONFIG_PATH = os.path.join(tmp, "config.json")
d.LOG_PATH    = os.path.join(tmp, "audit.log")
d.PROC_DIR    = os.path.join(tmp, "processes")
d.PROC_INDEX  = os.path.join(tmp, "processes.json")
d.ENVS_DIR    = os.path.join(tmp, "envs")
# Confine setup targets to tmp instead of the real $HOME for this test.
d.os.environ["HOME"] = tmp

ORIGIN   = "http://localhost:6161"
ORIGIN_B = "http://localhost:6262"   # a DIFFERENT trusted origin
d._update_config({"port": 0, "whitelist": [ORIGIN, ORIGIN_B], "graylist": [], "python": ""})

# Auto-approve any native dialog the daemon enqueues (stands in for the user).
_approver_stop = threading.Event()
def _approver():
    while not _approver_stop.is_set():
        try:
            item = d._dialog_queue.get(timeout=0.2)
        except queue.Empty:
            continue
        # item = (origin, summary, event, result, meta)
        result, event = item[3], item[2]
        result[0] = True
        event.set()
threading.Thread(target=_approver, daemon=True).start()

srv = ThreadingHTTPServer(("127.0.0.1", 0), d.Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

def post(path, body, origin=ORIGIN):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    headers = {"Host": "127.0.0.1", "Content-Type": "application/json"}
    if origin: headers["Origin"] = origin
    c.request("POST", path, json.dumps(body), headers)
    r = c.getresponse(); data = json.loads(r.read() or b"{}"); c.close()
    return r.status, data

def get(path, origin=ORIGIN):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    headers = {"Host": "127.0.0.1"}
    if origin: headers["Origin"] = origin
    c.request("GET", path, headers=headers)
    r = c.getresponse(); data = json.loads(r.read() or b"{}"); c.close()
    return r.status, data

try:
    print("validation / negative cases")
    st, _ = post("/setup-env", {"type": "venv", "name": "x"}, origin="http://evil.example")
    check("  untrusted origin -> 403", st, 403)
    st, data = post("/setup-env", {"type": "poetry", "name": "x"})
    check("  bad type -> 400", st, 400)
    st, data = post("/setup-env", {"type": "venv", "name": "x", "packages": ["--evil"]})
    check("  bad package -> 400", st, 400)
    st, data = post("/setup-env", {"type": "venv", "path": "/etc/w2l"})
    check("  path outside home -> 400", st, 400)
    st, data = post("/setup-env", {"type": "conda", "name": "x"})
    check("  conda not installed -> 400", st, 400)
    check("  conda error mentions conda", "conda" in (data.get("error", "")), True)

    print("create a real venv end-to-end")
    st, data = post("/setup-env", {"type": "venv", "name": "demo"})
    check("  setup accepted (running)", st, 200)
    check("  status running", data.get("status"), "running")
    job_id = data.get("job_id")
    check("  returned a job_id", bool(job_id), True)
    expected_interp = os.path.join(tmp, "envs", "demo", "bin", "python")
    check("  predicted interpreter path", data.get("interpreter"), expected_interp)

    # Poll until the job finishes.
    final = None
    for _ in range(300):  # up to ~60s
        st, s = get(f"/setup-env/status?job={job_id}")
        if st == 200 and s.get("status") in ("done", "failed"):
            final = s; break
        time.sleep(0.2)
    check("  job reached terminal state", bool(final), True)
    check("  job done", (final or {}).get("status"), "done")
    check("  interpreter exists on disk",
          os.path.isfile(expected_interp) and os.access(expected_interp, os.X_OK), True)

    # /env should now reflect the new interpreter (config["python"] was set).
    st, envd = get("/env")
    check("  /env interpreter == new venv", envd.get("interpreter"), expected_interp)
    check("  /env source == config", envd.get("source"), "config")

    # Re-running the same setup is idempotent: already exists -> ready, no job.
    st, data = post("/setup-env", {"type": "venv", "name": "demo"})
    check("  idempotent re-run -> ready", data.get("status"), "ready")
    check("  idempotent already_exists", data.get("already_exists"), True)

    print("setup is gated to trusted origins")
    st, _ = get("/setup-env/status?job=" + str(job_id), origin="http://evil.example")
    check("  status untrusted origin -> 403", st, 403)

    print("no silent adopt of an existing interpreter outside the sandbox (HIGH)")
    # Plant a real-looking env UNDER $HOME but OUTSIDE ENVS_DIR.
    outside = os.path.join(tmp, "proj", ".venv")
    os.makedirs(os.path.join(outside, "bin"), exist_ok=True)
    fake = os.path.join(outside, "bin", "python")
    with open(fake, "w") as f: f.write("#!/bin/sh\n")
    os.chmod(fake, 0o755)
    before = json.load(open(d.CONFIG_PATH)).get("python")
    st, data = post("/setup-env", {"type": "venv", "path": os.path.join(tmp, "proj", ".venv")})
    check("  non-sandbox existing env -> 400 (not silently adopted)", st, 400)
    after = json.load(open(d.CONFIG_PATH)).get("python")
    check("  config['python'] unchanged (no silent repoint)", after, before)

    print("a job is not visible to a different trusted origin (cross-origin scope)")
    st, _ = get(f"/setup-env/status?job={job_id}", origin=ORIGIN_B)
    check("  other trusted origin -> 404", st, 404)
finally:
    _approver_stop.set()
    srv.shutdown()

print()
if failures:
    print(f"{len(failures)} FAILED: {failures}"); sys.exit(1)
print("ALL PASSED")
