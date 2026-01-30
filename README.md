# macOS Fingerprint

[![CI](https://github.com/star7js/macos-fingerprint/actions/workflows/ci.yml/badge.svg)](https://github.com/star7js/macos-fingerprint/actions/workflows/ci.yml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/star7js/macos-fingerprint/branch/main/graph/badge.svg)](https://codecov.io/gh/star7js/macos-fingerprint)

A comprehensive, security-focused macOS system fingerprinting tool for detecting unauthorized changes to your Mac. Track installed applications, system configuration, network settings, security status, and developer environment.

## Features

### Comprehensive Data Collection

- **Applications**: Installed apps, browser extensions, launch agents, startup items
- **System**: macOS version, hardware info, kernel extensions, printers, Time Machine
- **Network**: Network configuration, open ports, connections, SSH config, hosts file, VPN, proxies
- **Security**: FileVault, firewall, SIP, Gatekeeper, XProtect, MRT versions
- **User**: User accounts on the system
- **Developer**: Homebrew packages, pip/npm global packages, Xcode version
- **Hardware**: Bluetooth devices, CPU/memory information

### Security Features

- **Sensitive Data Hashing**: By default, sensitive fields (IP addresses, MAC addresses, SSH known_hosts, ARP cache) are hashed using SHA-3 for quantum-resistance consideration
- **Encryption**: Optional AES-256-GCM encryption for stored fingerprints
- **Secure Storage**: Fingerprints saved with 0600 permissions (owner read/write only)
- **Integrity Verification**: HMAC-based integrity checking for stored data
- **Input Validation**: All commands and paths validated to prevent injection attacks

### Advanced Comparison

- **Diff-Style Output**: See exactly what was added, removed, or modified
- **Severity Classification**: Changes categorized as Critical, High, Medium, or Low
- **HTML Export**: Generate beautiful comparison reports
- **JSON Export**: Machine-readable comparison results

## Installation

### From Source

```bash
git clone https://github.com/star7js/macos-fingerprint.git
cd macos-fingerprint
pip install -e .
```

### With GUI Support

```bash
pip install -e ".[gui]"
```

### For Development

```bash
pip install -e ".[dev]"

# Install pre-commit hooks (recommended)
pip install pre-commit
pre-commit install
```

Pre-commit hooks will automatically run black, ruff, and mypy before each commit to ensure code quality.

## Usage

### Command Line Interface

#### Create a Baseline Fingerprint

```bash
# Basic usage
macos-fingerprint create -o baseline.json

# Without hashing sensitive fields
macos-fingerprint create -o baseline.json --no-hash

# With encryption
macos-fingerprint create -o secure.json --encrypt --password mypassword
```

#### Compare Current System to Baseline

```bash
# Basic comparison
macos-fingerprint compare -b baseline.json

# Export comparison as HTML report
macos-fingerprint compare -b baseline.json -o report.html --format html

# Export as JSON
macos-fingerprint compare -b baseline.json -o comparison.json

# Compare encrypted fingerprint
macos-fingerprint compare -b secure.json --encrypted --password mypassword
```

#### Calculate Fingerprint Hash

```bash
macos-fingerprint hash baseline.json
```

### Python API

```python
from macos_fingerprint import (
    create_fingerprint,
    save_fingerprint,
    load_fingerprint,
    compare_fingerprints,
    hash_fingerprint
)

# Create a fingerprint
fingerprint = create_fingerprint(hash_sensitive=True)

# Save it
save_fingerprint(fingerprint, "baseline.json")

# Load a fingerprint
baseline = load_fingerprint("baseline.json")

# Compare fingerprints
current = create_fingerprint()
differences = compare_fingerprints(baseline, current)

# Get hash
fp_hash = hash_fingerprint(fingerprint)
print(f"Fingerprint hash: {fp_hash}")
```

### GUI Application

```bash
macos-fingerprint-gui
```

The GUI provides:
- Visual fingerprint creation with progress tracking
- Side-by-side comparison
- Scheduled daily scans
- Multiple themes (Light, Dark, Custom)
- Auto-export options

## Privacy & Security

### What Data is Collected?

macOS Fingerprint collects system configuration information including:

- Lists of installed applications and extensions
- System settings and configurations
- Network interface configurations
- Security settings status
- User account names (not passwords)
- Hardware information

### What is Hashed?

By default, the following sensitive fields are hashed using SHA-3:

- IP addresses
- MAC addresses
- ARP cache entries
- SSH known_hosts entries
- WiFi network information (contains BSSIDs)
- Routing table entries

Hashing preserves the ability to detect changes while protecting the actual values from exposure.

### Encryption

Use the `--encrypt` flag to encrypt fingerprints with AES-256-GCM:

```bash
macos-fingerprint create -o secure.json --encrypt --password mysecurepassword
```

### Storage Security

- Fingerprint files are created with 0600 permissions (owner read/write only)
- All file operations include path sanitization to prevent traversal attacks
- No shell=True in subprocess calls
- Input validation on all command execution

## Use Cases

### Personal Security Monitoring

Create a baseline after setting up your Mac, then periodically compare to detect unauthorized changes:

```bash
# After initial setup
macos-fingerprint create -o ~/secure/baseline.json --encrypt --password [password]

# Weekly check
macos-fingerprint compare -b ~/secure/baseline.json --encrypted --password [password]
```

### System Administration

Track configuration changes across managed Macs:

```bash
# On managed systems
macos-fingerprint create -o "$(hostname)-$(date +%Y%m%d).json"

# Centralized comparison
for file in *.json; do
    macos-fingerprint compare -b baseline.json -o "comparison-$file"
done
```

### Incident Response

Document system state before and after suspicious activity:

```bash
# Before investigation
macos-fingerprint create -o pre-investigation.json

# After remediation
macos-fingerprint create -o post-remediation.json

# Generate report
macos-fingerprint compare -b pre-investigation.json -o incident-report.html --format html
```

### Developer Environment Tracking

Track development environment changes:

```bash
# Initial setup
macos-fingerprint create -o dev-environment-baseline.json

# After package installations/updates
macos-fingerprint compare -b dev-environment-baseline.json
```

## Architecture

```
macos_fingerprint/
├── core/
│   ├── fingerprint.py    # Main fingerprinting logic
│   ├── comparison.py     # Diff and severity classification
│   └── storage.py        # Secure file I/O
├── collectors/
│   ├── base.py           # BaseCollector and registry
│   ├── apps.py           # Application collectors
│   ├── system.py         # System info collectors
│   ├── network.py        # Network collectors
│   ├── security.py       # Security status collectors
│   ├── user.py           # User account collectors
│   └── developer.py      # Developer environment collectors
├── utils/
│   ├── commands.py       # Safe command execution
│   └── crypto.py         # Cryptographic utilities
├── cli.py                # Command-line interface
└── gui.py                # PyQt5 GUI application
```

### Collector Pattern

Each collector inherits from `BaseCollector` and implements a `collect()` method:

```python
from macos_fingerprint.collectors.base import BaseCollector, CollectorResult

class MyCollector(BaseCollector):
    def collect(self) -> CollectorResult:
        # Collect data
        data = get_my_data()

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )
```

## Requirements

- macOS 10.15 (Catalina) or later
- Python 3.8 or later
- cryptography >= 41.0.0
- PyQt5 >= 5.15.0 (for GUI)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for legitimate security monitoring and system administration purposes only. Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction.

## Support

- Report bugs: [GitHub Issues](https://github.com/star7js/macos-fingerprint/issues)
- Feature requests: [GitHub Discussions](https://github.com/star7js/macos-fingerprint/discussions)

## Changelog

### Version 2.0.0

- Complete refactor with modular architecture
- Added SHA-3 hashing for sensitive data
- Added AES-256-GCM encryption support
- Removed sudo requirement for open ports collector
- Fixed duplicate create_fingerprint() bug
- Improved error handling throughout
- Added developer environment collectors (Homebrew, pip, npm, Xcode)
- Enhanced comparison with severity classification
- HTML report generation
- Secure file storage with integrity verification
- Input validation and command sanitization
- PyQt5 GUI with threading support

### Version 1.0.0

- Initial release
- Basic fingerprinting functionality
- Simple comparison
