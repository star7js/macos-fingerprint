# macOS Fingerprint - Project Review & Roadmap

## Honest Assessment

This is a well-structured v2.0 with solid fundamentals: clean collector pattern, proper
encryption, good test scaffolding, and a working GUI. That said, there's a meaningful
gap between where it is now and something worth distributing — whether on the Mac App
Store or as a standalone download. Below is what I'd change and why, followed by a
phased roadmap.

---

## What I'd Do Differently

### 1. Fix the bugs that are already there

**CollectorRegistry is a mutable class-level singleton**
(`src/macos_fingerprint/collectors/base.py:75`)

```python
_collectors: Dict[str, BaseCollector] = {}
```

This dict is shared across all instances and lives for the entire process lifetime.
If `create_fingerprint()` is called twice, `register_all_collectors()` silently
skips re-registration because the dict is non-empty — but if collectors were
modified between calls (or tests cleared the registry), you get inconsistent state.
Replace this with an instance-based registry, or at minimum add idempotent
re-registration.

**BonjourServicesCollector will hang**
(`src/macos_fingerprint/collectors/network.py:165`)

```python
result = run_command(["dns-sd", "-B"])
```

`dns-sd -B` is a *continuous* discovery command — it never terminates on its own.
`run_command` has a 30-second timeout, but that means every fingerprint creation
blocks for 30 seconds waiting for this collector to time out and return None. Either
drop this collector or replace it with a bounded alternative.

**SSHConfigCollector and HostsFileCollector shell out to `cat`**
(`src/macos_fingerprint/collectors/network.py:118-119`)

```python
ssh_config = run_command(["cat", "/etc/ssh/sshd_config"])
known_hosts = run_command(["cat", os.path.expanduser("~/.ssh/known_hosts")])
```

The project already has `safe_read_file()` in `utils/commands.py` — a utility
specifically designed for this. Spawning `cat` as a subprocess to read a file is
unnecessary overhead and bypasses the file-size safety checks that `safe_read_file`
provides.

**Hardcoded HMAC key**
(`src/macos_fingerprint/utils/crypto.py:222`)

```python
_INTEGRITY_KEY = b"macos-fingerprint-integrity-v1"
```

This key is in the source code. Anyone with the source can recompute a valid HMAC
after modifying a fingerprint file. The integrity check provides a false sense of
security. Either derive the HMAC key from the user's password (when encryption is
used), or document clearly that the HMAC only guards against accidental corruption,
not tampering.

### 2. Architectural issues

**No structured logging.** Every error path uses `print()`. For a security tool,
you need proper log levels (DEBUG/INFO/WARNING/ERROR), structured output, and the
ability to route logs to files. Replace all `print()` calls with Python's `logging`
module.

**Sequential collection.** All 25 collectors run one after another. Many of them are
I/O-bound (waiting on subprocess calls). Using `concurrent.futures.ThreadPoolExecutor`
to run collectors in parallel would cut scan time significantly. The collector pattern
already supports this — `safe_collect()` is self-contained.

**GUI is a single 700-line file.** The `FingerPrintApp` class handles UI layout,
business logic, threading, theming, settings persistence, and scheduling all in one
place. Split it into: (1) a main window shell, (2) individual tab widgets,
(3) a controller/service layer that the tabs call into.

**No configuration file.** Everything is hardcoded or passed via CLI flags. A config
file (~/.macos-fingerprint/config.toml) would let users customize: which collectors
to run, output directory, hash algorithm, default encryption settings, notification
preferences, and ignored paths/changes.

### 3. Security gaps for a security tool

**CLI password is visible in the process table.** `--password mypassword` appears in
`ps aux` output. Provide a `--password-file` option or read from stdin when
`--password` is omitted but `--encrypt` is set (interactive prompt).

**The `validate_command` allowlist is too broad.** The osascript exemption
(`commands.py:63`) lets shell metacharacters through for any osascript invocation.
A more targeted approach would validate the specific osascript arguments expected.

**`compare_lists` loses ordering and duplicate information.** Converting to sets
(`comparison.py:78-79`) means if a list had `["a", "a", "b"]` and becomes
`["a", "b"]`, the removal of the duplicate `"a"` is silently ignored. For security
auditing, this matters.

### 4. What's missing for real-world use

| Gap | Why it matters |
|-----|----------------|
| No selective collectors | Users can't skip slow/irrelevant collectors |
| No ignore rules | Known changes trigger false positives every scan |
| No history/timeline | Only two-snapshot comparison; no trend analysis |
| No notifications | Critical changes detected but nobody finds out |
| No daemon mode | Scheduled scans require the GUI to be open |
| No machine-readable CLI output | Can't pipe JSON to other tools by default |
| 25% test coverage floor | Too low for a security tool people should trust |

---

## Mac App Store Feasibility

**Short answer: not realistic in the current form.**

The Mac App Store requires:
- **App Sandbox** — this tool spawns dozens of subprocess calls to system utilities
  (`networksetup`, `lsof`, `netstat`, `arp`, `defaults`, etc.). Sandboxing would
  break nearly every collector.
- **Native app bundle** — Python + PyQt5 can be packaged with PyInstaller or
  py2app, but it produces large bundles (200+ MB) and Apple's reviewers are
  skeptical of non-native frameworks.
- **Apple Developer ID signing and notarization** — required even for distribution
  outside the store.
- **No private API usage** — the `airport` binary
  (`/System/Library/PrivateFrameworks/Apple80211.framework/...`) is a private
  framework that Apple explicitly prohibits in store apps.

**Better distribution paths:**
1. **Homebrew tap** — `brew install star7js/tap/macos-fingerprint` — natural fit
   for the target audience (devs and sysadmins)
2. **Notarized DMG** — native-feeling distribution with Gatekeeper approval, no
   store dependency
3. **PyPI** — `pip install macos-fingerprint` — already set up in pyproject.toml

If you eventually want a store-quality native app, the right approach would be a
SwiftUI frontend that calls the Python collectors via an XPC service or embedded
Python runtime — a much larger undertaking.

---

## Roadmap

### Phase 1: Foundation Fixes (the bugs and gaps above)

- [ ] Replace `dns-sd -B` with a bounded alternative or remove BonjourServicesCollector
- [ ] Use `safe_read_file()` instead of shelling out to `cat` in SSH/Hosts collectors
- [ ] Make `CollectorRegistry` instance-based instead of class-level mutable state
- [ ] Replace all `print()` calls with Python `logging` module
- [ ] Fix `compare_lists` to preserve ordering/duplicates (use `Counter` or sequence diff)
- [ ] Add `--password-file` and stdin password prompt for secure password input
- [ ] Derive HMAC key from user password when encryption is enabled
- [ ] Raise test coverage floor to 60%

### Phase 2: Usability

- [ ] Add a config file (`~/.macos-fingerprint/config.toml`) for persistent settings
- [ ] Add `--collectors` flag to select which collectors run
- [ ] Add `--exclude` flag to skip specific collectors
- [ ] Add `--json` output mode to CLI for machine-readable output
- [ ] Add ignore rules (path patterns, collector names, known-change hashes)
- [ ] Run collectors in parallel with `concurrent.futures.ThreadPoolExecutor`
- [ ] Add per-collector progress callbacks so the GUI shows which collector is running
- [ ] Split `gui.py` into separate modules (tabs, controller, workers)

### Phase 3: Monitoring & Alerting

- [ ] Add a launchd plist generator (`macos-fingerprint install-daemon`) for
      background scheduled scans without the GUI
- [ ] Add macOS notification center integration for critical/high severity changes
- [ ] Add email/webhook alerting for unattended monitoring
- [ ] Add fingerprint history with SQLite storage for trend analysis
- [ ] Add a `timeline` CLI command that shows change history across baselines
- [ ] Add a `watch` CLI command for continuous monitoring mode

### Phase 4: Distribution & Polish

- [ ] Create a Homebrew formula and publish to a tap
- [ ] Build a notarized `.app` bundle with py2app for non-developer users
- [ ] Create a DMG with drag-to-Applications installer
- [ ] Add a menubar-only mode (no dock icon) for background monitoring
- [ ] Replace PyQt5 with a lighter alternative (e.g., rumps for menubar + webview
      for reports) to reduce bundle size
- [ ] Write a man page (`macos-fingerprint.1`)

### Phase 5: Advanced Features (longer term)

- [ ] **Swift/SwiftUI native GUI** — proper macOS-native interface that could
      eventually target the App Store
- [ ] **Fleet management** — central server that collects fingerprints from
      multiple machines, with a web dashboard
- [ ] **Collector plugins** — let users write custom collectors without modifying
      the core package
- [ ] **Differential baselines** — instead of comparing to a single baseline,
      track a rolling window and alert on anomalies
- [ ] **File integrity monitoring** — extend beyond system config to watch specific
      directories/files for changes (like AIDE or Tripwire)
- [ ] **Code signing verification** — verify that installed applications haven't
      been tampered with by checking code signatures

---

## Priority Recommendation

If I were working on this project, I'd tackle things in this order:

1. **Phase 1 first** — fix the bugs. The Bonjour hang and the singleton registry are
   the most impactful. These are correctness issues, not features.
2. **Parallel collection + config file from Phase 2** — biggest quality-of-life
   improvement for the least code change.
3. **Homebrew formula from Phase 4** — gets the tool in front of users immediately.
4. **Launchd daemon from Phase 3** — makes the tool actually useful for ongoing
   monitoring instead of one-off scans.

Everything else can follow based on what users actually ask for.
