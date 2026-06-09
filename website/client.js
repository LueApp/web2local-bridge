/**
 * web2local client library
 * Include this in any website that wants to talk to the local daemon.
 *
 * Usage:
 *   const w2l = new Web2Local();
 *   if (await w2l.isRunning()) {
 *     const r = await w2l.run("ls", ["-la", "/tmp"]);
 *     console.log(r.stdout);
 *   }
 */
class Web2Local {
  /**
   * @param {number} port - daemon port (default 7878)
   */
  constructor(port = 7878) {
    this.base = `http://127.0.0.1:${port}`;
  }

  /**
   * Check whether the local daemon is reachable.
   * @returns {Promise<boolean>}
   */
  async isRunning() {
    try {
      const r = await fetch(`${this.base}/status`);
      return r.ok;
    } catch {
      return false;
    }
  }

  /**
   * Return daemon status info.
   * @returns {Promise<{status:string, version:string}>}
   */
  async status() {
    const r = await fetch(`${this.base}/status`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  /**
   * Execute a command on the local machine.
   * - Whitelist origins: executed immediately.
   * - Graylist origins: user sees an approval dialog first.
   *
   * @param {string}   command  - executable name (no shell, no PATH tricks).
   *                              A bare "python"/"python3" is transparently
   *                              mapped to the user's selected env (pixi/conda/
   *                              venv); the page cannot choose the interpreter.
   * @param {string[]} args     - argument list
   * @returns {Promise<{stdout:string, stderr:string, exit_code:number}>}
   * @throws  on network error or if denied / not authorised
   */
  async run(command, args = []) {
    const r = await fetch(`${this.base}/run`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ command, args }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }

  /**
   * Read current whitelist / graylist config from the daemon.
   * @returns {Promise<{port:number, whitelist:string[], graylist:string[]}>}
   */
  async getConfig() {
    const r = await fetch(`${this.base}/config`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  /**
   * Add an origin to the whitelist (removes it from graylist if present).
   * @param {string} origin - e.g. "https://mysite.com"
   */
  async addToWhitelist(origin) {
    return this._postConfig("/config/whitelist", { origin });
  }

  /**
   * Add an origin to the graylist (removes it from whitelist if present).
   * @param {string} origin - e.g. "https://mysite.com"
   */
  async addToGraylist(origin) {
    return this._postConfig("/config/graylist", { origin });
  }

  /**
   * Remove an origin from both lists.
   * @param {string} origin
   */
  async removeOrigin(origin) {
    return this._postConfig("/config/remove", { origin });
  }

  /**
   * Fetch the last 200 audit log entries.
   * @returns {Promise<{entries:string[]}>}
   */
  async getLog() {
    const r = await fetch(`${this.base}/log`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  /**
   * Start a long-running process. Returns immediately with its PID.
   * Output is captured to a log file the daemon can tail via tailLog().
   *
   * @param {string}   command
   * @param {string[]} args
   * @returns {Promise<{pid:number, started_at:string, log_path:string}>}
   */
  async spawn(command, args = []) {
    const r = await fetch(`${this.base}/spawn`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ command, args }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }

  /**
   * List processes spawned via spawn() that are still alive.
   * @returns {Promise<{processes: Array}>}
   */
  async ps() {
    const r = await fetch(`${this.base}/ps`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  /**
   * Stop a process by PID. Sends SIGTERM, then SIGKILL after 3 s.
   * @param {number} pid
   * @returns {Promise<{status:string, signal?:string}>}
   */
  async stop(pid) {
    const r = await fetch(`${this.base}/stop`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ pid }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }

  /**
   * Tail the last 200 lines of a spawned process's output.
   * @param {number} pid
   * @returns {Promise<{pid:number, tail:string}>}
   */
  async tailLog(pid) {
    const r = await fetch(`${this.base}/logs?pid=${encodeURIComponent(pid)}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  /**
   * Fetch a script from the page's own origin, verify its SHA-256, hand
   * the source to the daemon, and spawn it — all in one round-trip.
   *
   * The daemon will ALWAYS show a native approval dialog before writing or
   * running anything, regardless of whitelist status.
   *
   * @param {object} opts
   * @param {string}   opts.source   - Full source of the script (UTF-8 string).
   * @param {string}   opts.sha256   - Expected SHA-256 hex digest (64 chars).
   *                                   Must match sha256(source); daemon rejects
   *                                   on mismatch before showing any dialog.
   * @param {string}   [opts.filename="agent.py"] - Suggested filename on disk.
   * @param {string}   opts.command  - Interpreter (e.g. "python3"). A bare
   *                                   "python"/"python3" is mapped daemon-side to
   *                                   the user's selected env (pixi/conda/venv);
   *                                   see getEnv() to inspect the resolution.
   * @param {string[]} [opts.args=[]] - Arguments passed after the script path.
   *
   * @returns {Promise<{pid:number, path:string, started_at:string,
   *                    log_path:string, already_running?:boolean}>}
   * @throws  if denied by user, sha256 mismatches, or daemon unreachable.
   */
  async deploy({ source, sha256, filename = "agent.py", command, args = [] }) {
    const r = await fetch(`${this.base}/deploy`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ source, sha256, filename, command, args }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }

  /**
   * Ask the daemon to trust this page's origin.
   * Shows a native dialog on first contact; returns immediately if already trusted.
   *
   * @param {object} [opts]
   * @param {string} [opts.origin] - Override the origin (default: window.location.origin)
   * @returns {Promise<{status:string, level:string}>}
   * @throws if blocked by user or daemon unreachable
   */
  async requestAccess({ origin } = {}) {
    const r = await fetch(`${this.base}/handshake`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ origin: origin || window.location.origin }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }

  /**
   * Inspect which python interpreter the daemon will use for a bare "python3"
   * request. Diagnostic only — reflects the script-independent decision
   * (config → active env → PATH fallback). The page never controls this.
   * @returns {Promise<{interpreter:string|null, source:string,
   *                    config_python:string,
   *                    active:{VIRTUAL_ENV:string, CONDA_PREFIX:string}}>}
   */
  async getEnv() {
    const r = await fetch(`${this.base}/env`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  /**
   * Select an existing Python environment or interpreter for future bare
   * "python3" requests. `path` must be an env prefix or Python executable under
   * the user's home directory. The daemon shows a native approval dialog before
   * persisting config["python"].
   *
   * @param {string} path - e.g. "~/.venv" or "~/miniconda3/envs/myapp".
   * @returns {Promise<{status:"selected", interpreter:string|null, source:string,
   *                    config_python:string, already_selected?:boolean}>}
   */
  async selectEnv(path) {
    const r = await fetch(`${this.base}/env/select`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ path }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }

  /**
   * Ask the daemon to CREATE a python environment when the user has none set up.
   * The user picks the type on your page; the daemon shows a native approval
   * dialog, then creates it asynchronously. On success it points config["python"]
   * at the new interpreter (so future bare "python3" calls resolve to it).
   *
   * The page never names the interpreter and can only target $HOME: pass a short
   * `name` (created under ~/.config/web2local/envs/<name>) or a `path` inside your
   * home directory.
   *
   * @param {object}   opts
   * @param {"venv"|"pixi"|"conda"} opts.type - Environment kind to create.
   * @param {string}   [opts.name]     - Sandbox env name (used if no path given).
   * @param {string}   [opts.path]     - Explicit location inside $HOME.
   * @param {string[]} [opts.packages] - Packages to install during setup.
   * @returns {Promise<{status:"running"|"ready", job_id?:string, log_path?:string,
   *                    target:string, interpreter:string, already_exists?:boolean}>}
   *   status "running" → poll setupEnvStatus(job_id). status "ready" → the env
   *   already existed and is now selected.
   * @throws if denied by the user, the type's tool is missing, or the path escapes $HOME.
   */
  async setupEnv({ type, name = "", path = "", packages = [] }) {
    const r = await fetch(`${this.base}/setup-env`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ type, name, path, packages }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }

  /**
   * Poll the progress of an async setupEnv() job.
   * @param {string} jobId - The job_id returned by setupEnv().
   * @returns {Promise<{job_id:string, type:string, target:string, status:string,
   *                    interpreter:string|null, error:string, tail:string}>}
   *   status is "running" | "done" | "failed"; `tail` is the live setup log.
   */
  async setupEnvStatus(jobId) {
    const r = await fetch(`${this.base}/setup-env/status?job=${encodeURIComponent(jobId)}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  /**
   * List scripts deployed via /deploy that are still on disk.
   * @returns {Promise<{agents: Array<{sha256,filename,dest_path,origin,deployed_at}>}>}
   */
  async listAgents() {
    const r = await fetch(`${this.base}/agents`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  /**
   * Delete a deployed script by its SHA-256 hash.
   * @param {string} sha256 - Full 64-char hex digest
   * @returns {Promise<{status:string}>}
   */
  async deleteAgent(sha256) {
    return this._postConfig("/agents/delete", { sha256 });
  }

  async _postConfig(path, body) {
    const r = await fetch(`${this.base}${path}`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }
}

// Expose as global for plain <script> inclusion
if (typeof window !== "undefined") window.Web2Local = Web2Local;
// Also export for module bundlers
if (typeof module !== "undefined") module.exports = { Web2Local };
