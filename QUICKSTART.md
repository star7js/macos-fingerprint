# Quick Start Guide - macOS Fingerprint v2.0

Get started with macOS Fingerprint in 5 minutes!

## Installation

```bash
cd macos_fingerprint
pip install -e .
```

For GUI support:
```bash
pip install -e ".[gui]"
```

## Your First Fingerprint

### 1. Create a Baseline

```bash
macos-fingerprint create -o my-baseline.json
```

This creates a fingerprint of your current system state.

### 2. Make a Change

Try installing or removing an app, changing a setting, etc.

### 3. Compare

```bash
macos-fingerprint compare -b my-baseline.json
```

You'll see:
- Summary of changes (Critical, High, Medium, Low severity)
- Detailed list of what changed

### 4. Generate Report

```bash
macos-fingerprint compare -b my-baseline.json -o report.html --format html
```

Open `report.html` in your browser for a beautiful visual report.

## Common Use Cases

### Personal Mac Security

Monitor your personal Mac for unauthorized changes:

```bash
# After fresh setup
macos-fingerprint create -o ~/secure/baseline.json --encrypt --password [secure-password]

# Weekly check
macos-fingerprint compare -b ~/secure/baseline.json --encrypted --password [secure-password]
```

### Development Environment

Track your dev environment:

```bash
# Initial state
macos-fingerprint create -o dev-env-baseline.json

# After brew install/npm install/etc
macos-fingerprint compare -b dev-env-baseline.json -o changes.html --format html
```

### System Administration

Before and after system maintenance:

```bash
# Before changes
macos-fingerprint create -o pre-maintenance.json

# After changes
macos-fingerprint create -o post-maintenance.json

# Manual comparison if needed
macos-fingerprint compare -b pre-maintenance.json
```

## GUI Usage

If you installed GUI support:

```bash
macos-fingerprint-gui
```

1. Go to "Scan" tab → Click "Create New Fingerprint"
2. Wait for scan to complete
3. Go to "Compare" tab → Click "Compare with Baseline"
4. View results in the text area

## Understanding Results

### Severity Levels

- **Critical**: Security-related changes (FileVault, Gatekeeper, SSH config)
- **High**: System-level changes (kernel extensions, launch agents, user accounts)
- **Medium**: Configuration changes or removals
- **Low**: Minor changes (new apps, minor config)

### Example Output

```
Comparison Summary:
  Total Changes: 5
  Critical: 0
  High: 1
  Medium: 2
  Low: 2

Found 5 changes.
  [HIGH] LaunchAgentsCollector
  [MEDIUM] InstalledAppsCollector
  [MEDIUM] NetworkConfigCollector
  [LOW] HomebrewCollector
  [LOW] PrintersCollector
```

## Privacy & Security

### What Gets Hashed?

By default, these sensitive fields are hashed (one-way SHA-3):
- IP addresses
- MAC addresses
- SSH known_hosts entries
- ARP cache
- WiFi network details (BSSIDs)

You can still detect changes, but actual values are protected.

### To Disable Hashing

```bash
macos-fingerprint create -o baseline.json --no-hash
```

### File Security

All fingerprint files are created with 0600 permissions (owner read/write only).

## Tips

1. **Create Baseline After Setup**: Create your baseline right after setting up a new Mac or after major configuration
2. **Regular Checks**: Run comparisons weekly or after any system changes
3. **Encrypted Baselines**: For sensitive systems, always use encryption
4. **HTML Reports**: Use HTML format for sharing with team or documentation
5. **Version Control**: Consider storing baseline fingerprints in version control (encrypted!)

## Troubleshooting

### "Permission denied" errors
Some collectors may fail without sudo. This is expected - the tool works without elevated privileges.

### GUI not opening
Make sure you installed with GUI support: `pip install -e ".[gui]"`

### Old fingerprint won't load
v2.0 cannot read v1.0 fingerprints. Create a new baseline.

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check [MIGRATION.md](MIGRATION.md) if upgrading from v1.0
- See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute

## Help

- GitHub Issues: Report bugs or request features
- Documentation: See README.md

## Example Workflow

```bash
# Day 1: Fresh Mac setup
macos-fingerprint create -o day1-baseline.json

# Week 1: Regular check
macos-fingerprint compare -b day1-baseline.json

# Month 1: Major update coming
macos-fingerprint create -o pre-update.json
# ... perform macOS update ...
macos-fingerprint compare -b pre-update.json -o update-changes.html --format html

# Month 1: New baseline after update
macos-fingerprint create -o month1-baseline.json
```

Happy fingerprinting! 🔒
