"""
Setup configuration for macOS Fingerprint.
"""

from setuptools import setup, find_packages
import os

# Read README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read version
version = {}
with open("src/macos_fingerprint/__init__.py", "r") as f:
    for line in f:
        if line.startswith("__version__"):
            exec(line, version)
            break

setup(
    name="macos-fingerprint",
    version=version.get("__version__", "2.0.0"),
    author="macOS Fingerprint Contributors",
    description="Comprehensive macOS system fingerprinting tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/star7js/macos-fingerprint",
    project_urls={
        "Bug Tracker": "https://github.com/star7js/macos-fingerprint/issues",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: MacOS :: MacOS X",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    extras_require={
        "gui": ["PyQt5>=5.15.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-qt>=4.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "macos-fingerprint=macos_fingerprint.cli:main",
            "macos-fingerprint-gui=macos_fingerprint.gui:main",
        ],
    },
)
