# Contributing to macOS Fingerprint

Thank you for considering contributing to macOS Fingerprint! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help make the community welcoming for everyone

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/star7js/macos-fingerprint/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - macOS version and Python version
   - Relevant log output or error messages

### Suggesting Features

1. Check [Discussions](https://github.com/star7js/macos-fingerprint/discussions) for existing proposals
2. Create a new discussion describing:
   - The problem you're trying to solve
   - Your proposed solution
   - Alternative solutions considered
   - Potential impact on existing functionality

### Contributing Code

#### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/star7js/macos-fingerprint.git
cd macos-fingerprint

# Install in development mode with all extras
pip install -e ".[dev,gui]"

# Run tests
pytest
```

#### Creating a New Collector

1. Create a new file in `src/macos_fingerprint/collectors/`
2. Inherit from `BaseCollector`
3. Implement the `collect()` method
4. Register in `core/fingerprint.py`

Example:

```python
from .base import BaseCollector, CollectorResult, CollectorCategory
from ..utils.commands import run_command

class MyCollector(BaseCollector):
    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.SYSTEM

    def collect(self) -> CollectorResult:
        result = run_command(["my-command"])
        data = result.split('\n') if result else []

        return CollectorResult(
            success=True,
            data=data,
            collector_name=self.name
        )
```

#### Code Style

- Follow PEP 8
- Use type hints where possible
- Write docstrings for all public functions/classes
- Keep functions focused and single-purpose
- Avoid over-engineering

#### Testing

- Write tests for new features
- Ensure all tests pass before submitting PR
- Include both unit and integration tests
- Mock subprocess calls in tests

```python
def test_my_collector(mocker):
    mocker.patch('subprocess.run', return_value=MockResult())
    collector = MyCollector()
    result = collector.collect()
    assert result.success
```

#### Security Considerations

- Never use `shell=True` in subprocess calls
- Validate all file paths
- Sanitize user input
- Don't expose sensitive data in logs
- Hash sensitive fields by default
- Use secure file permissions (0600)

#### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

#### PR Guidelines

- Clear, descriptive title
- Reference related issues
- Describe changes made
- Include screenshots for UI changes
- Update documentation if needed
- Add tests for new functionality

## Project Structure

```
macos_fingerprint/
├── src/macos_fingerprint/
│   ├── core/              # Core functionality
│   ├── collectors/        # Data collectors
│   ├── utils/             # Utilities
│   ├── cli.py             # CLI interface
│   └── gui.py             # GUI interface
├── tests/                 # Test suite
├── README.md              # User documentation
├── CONTRIBUTING.md        # This file
├── LICENSE                # MIT License
├── setup.py               # Setup configuration
├── pyproject.toml         # Build configuration
└── requirements.txt       # Dependencies
```

## Adding New Features

### New Collector

1. Determine category (APPS, SYSTEM, NETWORK, SECURITY, HARDWARE, USER, DEVELOPER)
2. Create collector class
3. Add to appropriate file in `collectors/`
4. Register in `core/fingerprint.py`
5. Add tests
6. Update README with new data collected

### New Comparison Feature

1. Modify `core/comparison.py`
2. Update severity classification if needed
3. Add tests
4. Update documentation

### New Export Format

1. Add export function to `core/comparison.py`
2. Update CLI to support new format
3. Add tests
4. Update documentation

## Documentation

- Keep README.md up to date
- Add docstrings to all public APIs
- Include examples for new features
- Update changelog in README.md

## Release Process

Maintainers will:

1. Update version in `src/macos_fingerprint/__init__.py`
2. Update changelog in README.md
3. Create git tag
4. Build and upload to PyPI
5. Create GitHub release

## Questions?

Feel free to:
- Open a discussion on GitHub
- Comment on existing issues
- Reach out to maintainers

Thank you for contributing!
