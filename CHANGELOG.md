# Changelog

All notable changes to macOS Fingerprint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-07-06

First tagged release. Builds on the 2.0.0 foundation with compliance auditing,
unattended monitoring, and the usability/hardening work from the roadmap.

### Added

#### CIS Benchmark Audit
- `audit` command scores the system against a pragmatic subset of the CIS Apple
  macOS Benchmark (23 Level 1 controls), with per-control remediation
- Indeterminate checks (missing privileges, not macOS) are excluded from the
  score rather than counted as passes or failures
- `--level`, `--format {text,json,html}`, and `-o/--output`; exits non-zero when
  any determinable check fails, for CI/monitoring use
- Self-contained, shareable HTML scorecard (inline CSS, light/dark)

#### Headless Monitoring Agent
- `agent` command for unattended scheduled monitoring (`run`, `history`,
  `verify`, `install`, `uninstall`)
- `agent install` generates and loads a launchd agent for background scans
- Append-only, hash-chained history log — a silently edited or deleted record
  breaks the chain and is detectable (`agent verify`)
- Optional drift detection against a saved baseline each cycle

#### Usability
- Config file (`~/.macos-fingerprint/config.toml`) for persistent settings
- `--collectors` / `--exclude` to select which collectors run
- `--json` machine-readable output across CLI commands
- Ignore rules (collector names to skip in comparisons)
- Parallel collection with a thread pool (`--parallel`) and per-collector
  progress callbacks
- `--password-file` and interactive stdin prompt for secure password entry

### Changed
- HMAC integrity key is derived from the user's password when encryption is used
- GUI split into `gui/app.py`, `gui/tabs.py`, and `gui/workers.py`
- `compare_lists` preserves ordering and duplicate information

### Fixed
- Removed `dns-sd -B` collector that could hang the scan for the full timeout
- SSH/Hosts collectors read files via `safe_read_file()` instead of shelling out
  to `cat`
- `CollectorRegistry` is instance-based rather than a class-level singleton

### CI
- Test coverage floor raised to 75% (207 tests, ~77% coverage)
- Stable `ci-success` gate for branch protection, independent of the test matrix

## [2.0.0] - 2026-01-29

### Added

#### New Collectors
- `SystemInfoCollector` - macOS version, hardware model, CPU, memory, hostname, uptime
- `GatekeeperCollector` - Gatekeeper status
- `XProtectCollector` - XProtect version
- `MRTCollector` - Malware Removal Tool version
- `HomebrewCollector` - Homebrew formulas and casks
- `PipPackagesCollector` - Global pip packages
- `NpmPackagesCollector` - Global npm packages
- `XcodeCollector` - Xcode version and path

#### Security Features
- SHA-3 (Keccak) hashing for sensitive data (IP addresses, MAC addresses, SSH keys, ARP cache)
- AES-256-GCM encryption for stored fingerprints
- Secure file permissions (0600) on all saved files
- HMAC-based integrity verification
- Input validation and command sanitization
- Path traversal protection

#### Comparison Features
- Severity classification (Critical, High, Medium, Low)
- Detailed diff-style output showing added/removed/modified items
- HTML report generation with beautiful styling
- JSON export with structured data
- Summary statistics (total changes by severity)

#### Architecture
- Modular design with `core/`, `collectors/`, `utils/` packages
- `BaseCollector` abstract class for all collectors
- `CollectorRegistry` for automatic collector discovery
- `CollectorResult` dataclass for structured results
- Type hints throughout codebase

#### CLI
- Modern argument-based CLI (not interactive menu)
- `create` command - Create fingerprints
- `compare` command - Compare fingerprints
- `hash` command - Calculate fingerprint hash
- Encryption support with `--encrypt` and `--password` flags
- Format selection for exports (JSON/HTML)

#### GUI
- Proper QThread implementation preventing UI freezes
- `FingerprintWorker` for background fingerprint creation
- `ComparisonWorker` for background comparison
- Real-time progress updates
- Status messages during operations

#### Documentation
- Comprehensive README with examples
- Quick Start guide
- Contributing guidelines
- Migration guide from v1 to v2
- API documentation in docstrings

#### Testing
- Unit tests for collectors
- Crypto utility tests
- Comparison logic tests
- Mocked subprocess calls
- Pytest fixtures

### Changed

#### Breaking Changes
- Fingerprint structure now nests collectors under `"collectors"` key
- CLI changed from interactive menu to command-based interface
- Python package name is `macos-fingerprint` (hyphenated)
- File permissions changed to 0600 (more restrictive)
- Open ports collector no longer requires sudo

#### Improvements
- All collectors now return structured `CollectorResult` objects
- Error handling improved - returns `None` instead of error strings
- GUI no longer freezes during operations
- Better separation of concerns (core/collectors/utils)
- More consistent naming conventions
- Added timeout protection (30s default) for all commands

### Fixed

#### Critical Bugs
- **Duplicate Function Bug**: Removed duplicate `create_fingerprint()` at lines 187-202 that was shadowing the first definition. This bug prevented 6 collectors from ever executing:
  - `get_open_ports`
  - `get_network_connections`
  - `get_ssh_config`
  - `get_hosts_file`
  - `get_network_shares`
  - `get_bonjour_services`

- **Security Import Bug**: Removed dependency on external `security` package that didn't exist, causing import errors

- **Error Handling Bug**: Fixed `run_command()` returning error strings instead of `None`, which broke `.split()` calls

- **Sudo Requirement**: Removed unnecessary `sudo` from `get_open_ports()`, making tool work without elevated privileges

#### Minor Fixes
- Fixed all collectors to handle `None` returns from `run_command()`
- Added proper exception handling for `FileNotFoundError`, `PermissionError`, `TimeoutExpired`
- Fixed GUI timer using proper delay mechanism
- Improved network configuration collector to handle empty results

### Removed
- Dependency on non-existent `security` package
- Sudo requirement for open ports collection
- Interactive menu system in CLI (replaced with commands)

### Security
- All sensitive data now hashed by default using SHA-3
- File permissions restricted to 0600 (owner only)
- No shell injection vulnerabilities (`shell=False` enforced)
- Input validation on all file paths and commands
- Optional encryption for stored fingerprints

### Deprecated
- Old v1.0 fingerprint format (cannot be loaded by v2.0)
- Interactive CLI menu (use commands instead)

## [1.0.0] - Original Release

### Initial Features
- Basic fingerprinting of macOS systems
- Simple comparison of fingerprints
- GUI with PyQt5
- JSON export
- 12 collectors:
  - Installed applications
  - Browser extensions
  - Launch agents
  - Kernel extensions
  - Network configuration
  - Security settings
  - User accounts
  - Printers
  - Bluetooth devices
  - Time Machine
  - Startup items

### Known Issues in v1.0
- Duplicate `create_fingerprint()` function prevented 6 collectors from running
- External `security` package dependency caused import errors
- Poor error handling with string returns
- Required sudo for open ports
- No sensitive data hashing
- No encryption support
- GUI freezing during scans
- Inconsistent error handling

---

## Migration Notes

### From v1.0 to v2.0

**Breaking Changes:**
1. Fingerprint format changed - create new baselines
2. CLI interface changed - use commands instead of menu
3. File permissions more restrictive (0600)

**Benefits:**
1. All collectors now work (duplicate function bug fixed)
2. Better security with hashing and encryption
3. Improved comparison with severity classification
4. No sudo required
5. Better GUI responsiveness

See [MIGRATION.md](MIGRATION.md) for detailed migration guide.

---

## Versioning

This project follows [Semantic Versioning](https://semver.org/):
- MAJOR version for incompatible API changes
- MINOR version for new functionality in a backwards compatible manner
- PATCH version for backwards compatible bug fixes

---

## Links

- [Homepage](https://github.com/star7js/macos-fingerprint)
- [Issue Tracker](https://github.com/star7js/macos-fingerprint/issues)
- [Documentation](README.md)
- [Contributing](CONTRIBUTING.md)
