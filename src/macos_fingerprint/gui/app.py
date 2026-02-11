"""
Main application window for the MacBook Fingerprint GUI.
"""

import sys
import json
from datetime import datetime, timedelta

from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QTabWidget,
    QWidget,
    QVBoxLayout,
    QLabel,
    QHBoxLayout,
    QStyle,
    QMessageBox,
    QFileDialog,
    QColorDialog,
)
from PyQt5.QtCore import QTimer, Qt, QSettings
from PyQt5.QtGui import QFont, QPalette, QColor

from ..core.storage import save_fingerprint, load_fingerprint
from ..core.comparison import (
    export_comparison_html,
    export_comparison_json,
)
from .workers import FingerprintWorker, ComparisonWorker
from .tabs import ScanTab, CompareTab, ScheduleTab, SettingsTab


class FingerPrintApp(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.init_data()
        self.init_ui()
        self.load_settings()
        self.apply_theme()

    def init_data(self):
        """Initialize application data."""
        self.settings = QSettings("MacBookFingerprint", "MacBookFingerprint")
        self.current_fingerprint = None
        self.baseline_fingerprint = None
        self.last_comparison = None
        self.theme = self.settings.value("theme", "light")
        self.custom_colors = {
            "background": self.settings.value("custom_background", "#FFFFFF"),
            "text": self.settings.value("custom_text", "#000000"),
            "button": self.settings.value("custom_button", "#E0E0E0"),
        }
        self.worker = None
        # Collect action buttons so we can disable them during operations.
        self._action_buttons = []

    def init_ui(self):
        """Initialize user interface."""
        self.setWindowTitle("MacBook FingerPrint v2.0")
        self.setGeometry(100, 100, 900, 700)
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.setup_header()
        self.setup_tabs()
        self.setup_status_bar()

    def setup_header(self):
        """Set up application header."""
        header_layout = QHBoxLayout()
        logo_label = QLabel()
        logo_label.setPixmap(
            self.style()
            .standardPixmap(QStyle.SP_DriveHDIcon)
            .scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        )
        header_layout.addWidget(logo_label)

        title_label = QLabel("MacBook FingerPrint")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        self.layout.addLayout(header_layout)

    def setup_tabs(self):
        """Set up tab widget."""
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Arial", 12))
        self.layout.addWidget(self.tabs)

        self.scan_tab = ScanTab(self)
        self.compare_tab = CompareTab(self)
        self.schedule_tab = ScheduleTab(self)
        self.settings_tab = SettingsTab(self)

        self.tabs.addTab(
            self.scan_tab,
            self.style().standardIcon(QStyle.SP_FileIcon), "Scan",
        )
        self.tabs.addTab(
            self.compare_tab,
            self.style().standardIcon(QStyle.SP_FileDialogDetailedView), "Compare",
        )
        self.tabs.addTab(
            self.schedule_tab,
            self.style().standardIcon(QStyle.SP_FileDialogInfoView), "Schedule",
        )
        self.tabs.addTab(
            self.settings_tab,
            self.style().standardIcon(QStyle.SP_FileDialogInfoView), "Settings",
        )

    def setup_status_bar(self):
        """Set up status bar."""
        self.statusBar().showMessage("Ready")
        self.statusBar().setFont(QFont("Arial", 10))

    # ------------------------------------------------------------------
    # Button enable / disable helpers
    # ------------------------------------------------------------------

    def _set_buttons_enabled(self, enabled: bool):
        """Enable or disable all action buttons."""
        for button in self._action_buttons:
            button.setEnabled(enabled)

    # ------------------------------------------------------------------
    # Scan / create fingerprint
    # ------------------------------------------------------------------

    def create_fingerprint(self):
        """Create a new fingerprint using worker thread."""
        if self.worker and self.worker.isRunning():
            return

        self._set_buttons_enabled(False)
        self.scan_tab.progress.setVisible(True)
        self.scan_tab.progress.setRange(0, 0)  # Indeterminate progress
        self.update_status("Creating fingerprint...")

        self.worker = FingerprintWorker(hash_sensitive=True, parallel=True)
        self.worker.finished.connect(self.on_fingerprint_created)
        self.worker.error.connect(self.on_fingerprint_error)
        self.worker.progress.connect(self.on_fingerprint_progress)
        self.worker.start()

    def on_fingerprint_created(self, fingerprint):
        """Handle successful fingerprint creation."""
        self.current_fingerprint = fingerprint
        self.scan_tab.result.setText(json.dumps(self.current_fingerprint, indent=2))
        self.scan_tab.progress.setVisible(False)
        self.scan_tab.status.setText("")
        self._set_buttons_enabled(True)
        self.update_status("Fingerprint created", 5000)

        if self.settings_tab.auto_export_checkbox.isChecked():
            self.export_fingerprint()

        # If this was a scheduled scan, chain the comparison now that
        # creation is complete (avoids the previous fixed-timer race).
        if getattr(self, "_pending_scheduled_compare", False):
            self._pending_scheduled_compare = False
            self.compare_fingerprints()

    def on_fingerprint_error(self, error):
        """Handle fingerprint creation error."""
        self.scan_tab.progress.setVisible(False)
        self.scan_tab.status.setText("")
        self._set_buttons_enabled(True)
        self.show_error("Failed to create fingerprint", error)

    def on_fingerprint_progress(self, message):
        """Update progress message."""
        self.scan_tab.status.setText(message)

    # ------------------------------------------------------------------
    # Compare
    # ------------------------------------------------------------------

    def load_baseline_file(self):
        """Let the user pick a baseline fingerprint file."""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select Baseline Fingerprint",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if not filename:
            return

        loaded = load_fingerprint(filename)
        if loaded:
            self.baseline_fingerprint = loaded
            # Show just the filename, not the full path.
            short = filename.rsplit("/", 1)[-1]
            self.compare_tab.baseline_label.setText(f"Baseline: {short}")
            self.update_status(f"Baseline loaded from {short}", 5000)
        else:
            self.show_warning(
                "Load Failed", f"Could not load fingerprint from {filename}"
            )

    def compare_fingerprints(self):
        """Compare current system with baseline."""
        if self.worker and self.worker.isRunning():
            return

        try:
            # Use the explicitly-loaded baseline, or fall back to default file.
            if not self.baseline_fingerprint:
                self.baseline_fingerprint = load_fingerprint(
                    "fingerprint_baseline.json"
                )
            if not self.baseline_fingerprint:
                raise FileNotFoundError(
                    "No baseline fingerprint found. Create one first, or use "
                    "'Load Baseline...' to select a file."
                )

            self._set_buttons_enabled(False)
            self.compare_tab.progress.setVisible(True)
            self.compare_tab.progress.setRange(0, 0)
            self.update_status("Comparing fingerprints...")

            self.worker = ComparisonWorker(
                self.baseline_fingerprint, hash_sensitive=True, parallel=True
            )
            self.worker.finished.connect(self.on_comparison_complete)
            self.worker.error.connect(self.on_comparison_error)
            self.worker.progress.connect(self.on_comparison_progress)
            self.worker.start()

        except Exception as e:
            self.show_warning("Failed to load baseline", str(e))

    def on_comparison_complete(self, differences):
        """Handle successful comparison."""
        self.last_comparison = differences
        self.compare_tab.progress.setVisible(False)
        self.compare_tab.status.setText("")
        self._set_buttons_enabled(True)

        summary = differences["summary"]
        if summary["total_changes"] == 0:
            self.compare_tab.result.setText("No differences found.")
            self.update_status("Comparison complete - no differences", 5000)
        else:
            result_text = "Comparison Summary:\n"
            result_text += f"Total Changes: {summary['total_changes']}\n"
            result_text += f"Critical: {summary['critical']}\n"
            result_text += f"High: {summary['high']}\n"
            result_text += f"Medium: {summary['medium']}\n"
            result_text += f"Low: {summary['low']}\n\n"
            result_text += json.dumps(differences, indent=2)

            self.compare_tab.result.setText(result_text)
            self.update_status("Comparison complete - differences found", 5000)

        if self.settings_tab.auto_export_checkbox.isChecked():
            self.export_comparison()

    def on_comparison_error(self, error):
        """Handle comparison error."""
        self.compare_tab.progress.setVisible(False)
        self.compare_tab.status.setText("")
        self._set_buttons_enabled(True)
        self.show_error("Comparison Failed", error)

    def on_comparison_progress(self, message):
        """Update comparison progress message."""
        self.compare_tab.status.setText(message)

    # ------------------------------------------------------------------
    # Schedule
    # ------------------------------------------------------------------

    def schedule_scan(self):
        """Schedule a daily scan."""
        try:
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.scheduled_scan)
            self.timer.start(24 * 60 * 60 * 1000)  # 24 hours
            next_scan = datetime.now() + timedelta(days=1)
            next_scan = next_scan.replace(hour=0, minute=0, second=0, microsecond=0)
            self.schedule_tab.schedule_label.setText(
                f"Next scheduled scan: {next_scan.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            self.update_status("Daily scan scheduled", 5000)
        except Exception as e:
            self.show_warning("Failed to schedule scan", str(e))

    def scheduled_scan(self):
        """Execute scheduled scan and compare after creation completes."""
        self._pending_scheduled_compare = True
        self.create_fingerprint()

    def cancel_scheduled_scan(self):
        """Cancel scheduled scan."""
        if hasattr(self, "timer"):
            self.timer.stop()
            self.schedule_tab.schedule_label.setText("Next scheduled scan: Not set")
            self.update_status("Scheduled scan cancelled", 5000)
        else:
            self.show_info("No scheduled scan to cancel")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_fingerprint(self):
        """Export current fingerprint."""
        if not self.current_fingerprint:
            self.show_warning("No Fingerprint", "Create a fingerprint first")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Fingerprint", "", "JSON Files (*.json)"
        )
        if filename:
            if save_fingerprint(self.current_fingerprint, filename):
                self.update_status(f"Fingerprint exported to {filename}", 5000)
            else:
                self.show_error("Export Failed", "Could not save fingerprint")

    def export_comparison(self):
        """Export comparison results."""
        if not self.last_comparison:
            self.show_warning("No Comparison", "Run a comparison first")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Comparison", "", "JSON Files (*.json);;HTML Files (*.html)"
        )
        if filename:
            try:
                if filename.endswith(".html"):
                    if export_comparison_html(self.last_comparison, filename):
                        self.update_status(f"Comparison exported to {filename}", 5000)
                    else:
                        self.show_error("Export Failed", "Could not write HTML file")
                else:
                    if export_comparison_json(self.last_comparison, filename):
                        self.update_status(f"Comparison exported to {filename}", 5000)
                    else:
                        self.show_error("Export Failed", "Could not write JSON file")
            except Exception as e:
                self.show_error("Export Failed", str(e))

    # ------------------------------------------------------------------
    # Theme / settings
    # ------------------------------------------------------------------

    def on_theme_changed(self, theme):
        """Handle theme change."""
        self.theme = theme.lower()
        self._update_custom_color_visibility()
        self.apply_theme()

    def _update_custom_color_visibility(self):
        """Show custom color buttons only when the Custom theme is selected."""
        visible = self.theme == "custom"
        for button in self.settings_tab.custom_color_buttons.values():
            button.setVisible(visible)

    def choose_custom_color(self, color_name):
        """Choose custom color."""
        color = QColorDialog.getColor()
        if color.isValid():
            self.custom_colors[color_name] = color.name()
            self.settings_tab.custom_color_buttons[color_name].setStyleSheet(
                f"background-color: {color.name()};"
            )
        self.apply_theme()

    def apply_theme(self):
        """Apply selected theme."""
        if self.theme == "dark":
            self.set_dark_theme()
        elif self.theme == "light":
            self.set_light_theme()
        elif self.theme == "custom":
            self.set_custom_theme()

    def set_dark_theme(self):
        """Apply dark theme."""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        QApplication.setPalette(dark_palette)

    def set_light_theme(self):
        """Apply light theme."""
        QApplication.setPalette(QApplication.style().standardPalette())

    def set_custom_theme(self):
        """Apply custom theme."""
        custom_palette = QPalette()
        custom_palette.setColor(
            QPalette.Window, QColor(self.custom_colors["background"])
        )
        custom_palette.setColor(QPalette.WindowText, QColor(self.custom_colors["text"]))
        custom_palette.setColor(QPalette.Base, QColor(self.custom_colors["background"]))
        custom_palette.setColor(
            QPalette.AlternateBase,
            QColor(self.custom_colors["background"]).lighter(110),
        )
        custom_palette.setColor(
            QPalette.ToolTipBase, QColor(self.custom_colors["text"])
        )
        custom_palette.setColor(
            QPalette.ToolTipText, QColor(self.custom_colors["text"])
        )
        custom_palette.setColor(QPalette.Text, QColor(self.custom_colors["text"]))
        custom_palette.setColor(QPalette.Button, QColor(self.custom_colors["button"]))
        custom_palette.setColor(QPalette.ButtonText, QColor(self.custom_colors["text"]))
        custom_palette.setColor(QPalette.BrightText, Qt.red)
        custom_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        custom_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        custom_palette.setColor(
            QPalette.HighlightedText, QColor(self.custom_colors["background"])
        )
        QApplication.setPalette(custom_palette)

    def save_settings(self):
        """Save application settings."""
        self.settings.setValue(
            "auto_export", self.settings_tab.auto_export_checkbox.isChecked()
        )
        self.settings.setValue("theme", self.theme)
        for color_name, color_value in self.custom_colors.items():
            self.settings.setValue(f"custom_{color_name}", color_value)
        self.update_status("Settings saved", 5000)

    def load_settings(self):
        """Load application settings."""
        self.settings_tab.auto_export_checkbox.setChecked(
            self.settings.value("auto_export", False, type=bool)
        )
        self.theme = self.settings.value("theme", "light")
        self.settings_tab.theme_combo.setCurrentText(self.theme.capitalize())
        for color_name in self.custom_colors:
            self.custom_colors[color_name] = self.settings.value(
                f"custom_{color_name}", self.custom_colors[color_name]
            )
            self.settings_tab.custom_color_buttons[color_name].setStyleSheet(
                f"background-color: {self.custom_colors[color_name]};"
            )
        self._update_custom_color_visibility()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def update_status(self, message, timeout=0):
        """Update status bar message."""
        self.statusBar().showMessage(message, timeout)

    def show_error(self, title, message):
        """Show error message."""
        QMessageBox.critical(self, title, message)

    def show_warning(self, title, message):
        """Show warning message."""
        QMessageBox.warning(self, title, message)

    def show_info(self, message):
        """Show info message."""
        QMessageBox.information(self, "Info", message)

    def closeEvent(self, event):
        """Handle window close event."""
        self.save_settings()
        if self.worker and self.worker.isRunning():
            self.worker.quit()
            self.worker.wait()
        event.accept()


def main():
    """Main GUI entry point."""
    app = QApplication(sys.argv)
    window = FingerPrintApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
