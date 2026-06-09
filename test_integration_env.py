#!/usr/bin/env python3
"""Live HTTP integration test: prove /run and /env actually rewrite the
interpreter through the real Handler. Uses a temp config dir so it never touches
the user's ~/.config/web2local."""
import http.client
import importlib.util
import json
import os
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

tmp = tempfile.mkdtemp(prefix="w2l-itest-")
# Redirect all on-disk state into the temp dir.
d.CONFIG_DIR  = tmp
d.CONFIG_PATH = os.path.join(tmp, "config.json")
d.LOG_PATH    = os.path.join(tmp, "audit.log")
d.PROC_DIR    = os.path.join(tmp, "processes")
d.PROC_INDEX  = os.path.join(tmp, "processes.json")
d.AGENTS_DIR  = os.path.join(tmp, "agents")

ORIGIN = "http://localhost:5555"
REAL_PY = sys.executable  # point the override at the interpreter running this test
d._update_config({"port": 0, "whitelist": [ORIGIN], "graylist": [], "python": REAL_PY})

# A script that reports which interpreter actually executed it.
script = os.path.join(tmp, "whoami.py")
with open(script, "w") as f:
    f.write("import sys; print(sys.executable)\n")

srv = ThreadingHTTPServer(("127.0.0.1", 0), d.Handler)
port = srv.server_address[1]
th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()

def post(path, body, origin=ORIGIN):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {"Host": "127.0.0.1", "Content-Type": "application/json"}
    if origin: headers["Origin"] = origin
    c.request("POST", path, json.dumps(body), headers)
    r = c.getresponse(); data = json.loads(r.read() or b"{}"); c.close()
    return r.status, data

def get(path, origin=ORIGIN):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {"Host": "127.0.0.1"}
    if origin: headers["Origin"] = origin
    c.request("GET", path, headers=headers)
    r = c.getresponse(); data = json.loads(r.read() or b"{}"); c.close()
    return r.status, data

try:
    print("/env reports the configured interpreter")
    st, data = get("/env")
    check("  /env status 200", st, 200)
    check("  /env interpreter == configured python", data.get("interpreter"), REAL_PY)
    check("  /env source == config", data.get("source"), "config")

    print("/env is gated to trusted origins")
    st, data = get("/env", origin="http://evil.example")
    check("  untrusted origin gets 403", st, 403)

    print("/run executes under the configured interpreter")
    st, data = post("/run", {"command": "python3", "args": [script]})
    check("  /run status 200", st, 200)
    check("  /run exit_code 0", data.get("exit_code"), 0)
    # The script printed sys.executable — it must equal the override, NOT whatever
    # python3 the daemon process itself is (here they're the same binary, but the
    # point is the rewrite path is exercised: command was "python3").
    check("  script ran under configured interpreter",
          (data.get("stdout") or "").strip(), REAL_PY)

    print("/run leaves a non-python command untouched")
    st, data = post("/run", {"command": "echo", "args": ["hello"]})
    check("  echo status 200", st, 200)
    check("  echo stdout", (data.get("stdout") or "").strip(), "hello")

    # Audit log should show the resolved absolute interpreter, not bare "python3".
    print("audit log shows resolved interpreter")
    with open(d.LOG_PATH) as f:
        log = f.read()
    check("  audit contains resolved path", REAL_PY in log, True)
    check("  audit ALLOWED whitelist", "whitelist" in log, True)
finally:
    srv.shutdown()

print()
if failures:
    print(f"{len(failures)} FAILED: {failures}"); sys.exit(1)
print("ALL PASSED")
