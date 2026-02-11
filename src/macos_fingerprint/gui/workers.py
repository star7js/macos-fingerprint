"""
Background worker threads for the GUI.
"""

from PyQt5.QtCore import QThread, pyqtSignal

from ..core.fingerprint import create_fingerprint
from ..core.comparison import compare_fingerprints


class FingerprintWorker(QThread):
    """Worker thread for fingerprint creation to prevent UI freezing."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, hash_sensitive=True, parallel=False):
        super().__init__()
        self.hash_sensitive = hash_sensitive
        self.parallel = parallel

    def _on_progress(self, name, idx, total):
        self.progress.emit(f"[{idx + 1}/{total}] Collecting {name}...")

    def run(self):
        """Execute fingerprint creation in background."""
        try:
            self.progress.emit("Collecting system information...")
            fingerprint = create_fingerprint(
                hash_sensitive=self.hash_sensitive,
                parallel=self.parallel,
                progress_callback=self._on_progress,
            )
            self.progress.emit("Fingerprint created successfully")
            self.finished.emit(fingerprint)
        except Exception as e:
            self.error.emit(str(e))


class ComparisonWorker(QThread):
    """Worker thread for fingerprint comparison."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, baseline, hash_sensitive=True, parallel=False):
        super().__init__()
        self.baseline = baseline
        self.hash_sensitive = hash_sensitive
        self.parallel = parallel

    def _on_progress(self, name, idx, total):
        self.progress.emit(f"[{idx + 1}/{total}] Collecting {name}...")

    def run(self):
        """Execute comparison in background."""
        try:
            self.progress.emit("Creating current fingerprint...")
            current = create_fingerprint(
                hash_sensitive=self.hash_sensitive,
                parallel=self.parallel,
                progress_callback=self._on_progress,
            )
            self.progress.emit("Comparing fingerprints...")
            differences = compare_fingerprints(self.baseline, current)
            self.progress.emit("Comparison complete")
            self.finished.emit(differences)
        except Exception as e:
            self.error.emit(str(e))
