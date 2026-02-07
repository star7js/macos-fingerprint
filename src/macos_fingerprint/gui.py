"""
PyQt5 GUI for MacBook Fingerprint tool.
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
    QPushButton,
    QTextEdit,
    QLabel,
    QHBoxLayout,
    QStyle,
    QProgressBar,
    QMessageBox,
    QFileDialog,
    QCheckBox,
    QComboBox,
    QColorDialog,
)
from PyQt5.QtCore import QTimer, Qt, QSettings, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor

from .core.fingerprint import create_fingerprint
from .core.storage import save_fingerprint, load_fingerprint
from .core.comparison import compare_fingerprints


class FingerprintWorker(QThread):
    """Worker thread for fingerprint creation to prevent UI freezing."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, hash_sensitive=True):
        super().__init__()
        self.hash_sensitive = hash_sensitive

    def run(self):
        """Execute fingerprint creation in background."""
        try:
            self.progress.emit("Collecting system information...")
            fingerprint = create_fingerprint(hash_sensitive=self.hash_sensitive)
            self.progress.emit("Fingerprint created successfully")
            self.finished.emit(fingerprint)
        except Exception as e:
            self.error.emit(str(e))


class ComparisonWorker(QThread):
    """Worker thread for fingerprint comparison."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, baseline, hash_sensitive=True):
        super().__init__()
        self.baseline = baseline
        self.hash_sensitive = hash_sensitive

    def run(self):
        """Execute comparison in background."""
        try:
            self.progress.emit("Creating current fingerprint...")
            current = create_fingerprint(hash_sensitive=self.hash_sensitive)
            self.progress.emit("Comparing fingerprints...")
            differences = compare_fingerprints(self.baseline, current)
            self.progress.emit("Comparison complete")
            self.finished.emit(differences)
        except Exception as e:
            self.error.emit(str(e))


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
        self.theme = self.settings.value("theme", "light")
        self.custom_colors = {
            "background": self.settings.value("custom_background", "#FFFFFF"),
            "text": self.settings.value("custom_text", "#000000"),
            "button": self.settings.value("custom_button", "#E0E0E0"),
        }
        self.worker = None

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

        self.setup_scan_tab()
        self.setup_compare_tab()
        self.setup_schedule_tab()
        self.setup_settings_tab()

    def setup_scan_tab(self):
        """Set up scan tab."""
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)

        scan_button = self.create_button(
            "Create New Fingerprint", QStyle.SP_BrowserReload, self.create_fingerprint
        )
        scan_layout.addWidget(scan_button)

        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        scan_layout.addWidget(self.scan_progress)

        self.scan_status = QLabel("")
        self.scan_status.setFont(QFont("Arial", 10))
        scan_layout.addWidget(self.scan_status)

        self.scan_result = self.create_text_edit()
        scan_layout.addWidget(self.scan_result)

        export_button = self.create_button(
            "Export Fingerprint", QStyle.SP_DialogSaveButton, self.export_fingerprint
        )
        scan_layout.addWidget(export_button)

        self.tabs.addTab(
            scan_tab, self.style().standardIcon(QStyle.SP_FileIcon), "Scan"
        )

    def setup_compare_tab(self):
        """Set up compare tab."""
        compare_tab = QWidget()
        compare_layout = QVBoxLayout(compare_tab)

        compare_button = self.create_button(
            "Compare with Baseline",
            QStyle.SP_FileDialogContentsView,
            self.compare_fingerprints,
        )
        compare_layout.addWidget(compare_button)

        self.compare_progress = QProgressBar()
        self.compare_progress.setVisible(False)
        compare_layout.addWidget(self.compare_progress)

        self.compare_status = QLabel("")
        self.compare_status.setFont(QFont("Arial", 10))
        compare_layout.addWidget(self.compare_status)

        self.compare_result = self.create_text_edit()
        compare_layout.addWidget(self.compare_result)

        export_button = self.create_button(
            "Export Comparison", QStyle.SP_DialogSaveButton, self.export_comparison
        )
        compare_layout.addWidget(export_button)

        self.tabs.addTab(
            compare_tab,
            self.style().standardIcon(QStyle.SP_FileDialogDetailedView),
            "Compare",
        )

    def setup_schedule_tab(self):
        """Set up schedule tab."""
        schedule_tab = QWidget()
        schedule_layout = QVBoxLayout(schedule_tab)

        self.schedule_label = QLabel("Next scheduled scan: Not set")
        self.schedule_label.setFont(QFont("Arial", 12))
        schedule_layout.addWidget(self.schedule_label)

        schedule_button = self.create_button(
            "Schedule Daily Scan", QStyle.SP_BrowserReload, self.schedule_scan
        )
        schedule_layout.addWidget(schedule_button)

        cancel_schedule_button = self.create_button(
            "Cancel Scheduled Scan", QStyle.SP_BrowserStop, self.cancel_scheduled_scan
        )
        schedule_layout.addWidget(cancel_schedule_button)

        schedule_layout.addStretch()

        self.tabs.addTab(
            schedule_tab,
            self.style().standardIcon(QStyle.SP_FileDialogInfoView),
            "Schedule",
        )

    def setup_settings_tab(self):
        """Set up settings tab."""
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)

        self.auto_export_checkbox = QCheckBox("Auto-export results")
        settings_layout.addWidget(self.auto_export_checkbox)

        theme_label = QLabel("Theme:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark", "Custom"])
        self.theme_combo.setCurrentText(self.theme.capitalize())
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        settings_layout.addWidget(theme_label)
        settings_layout.addWidget(self.theme_combo)

        self.custom_color_buttons = {}
        for color_name in ["background", "text", "button"]:
            button = QPushButton(f"Choose {color_name.capitalize()} Color")
            button.clicked.connect(
                lambda _, cn=color_name: self.choose_custom_color(cn)
            )
            settings_layout.addWidget(button)
            self.custom_color_buttons[color_name] = button

        save_settings_button = self.create_button(
            "Save Settings", QStyle.SP_DialogSaveButton, self.save_settings
        )
        settings_layout.addWidget(save_settings_button)

        settings_layout.addStretch()

        self.tabs.addTab(
            settings_tab,
            self.style().standardIcon(QStyle.SP_FileDialogInfoView),
            "Settings",
        )

    def setup_status_bar(self):
        """Set up status bar."""
        self.statusBar().showMessage("Ready")
        self.statusBar().setFont(QFont("Arial", 10))

    def create_button(self, text, icon, connection):
        """Create a styled button."""
        button = QPushButton(text)
        button.setIcon(self.style().standardIcon(icon))
        button.setFont(QFont("Arial", 14))
        button.setMinimumHeight(50)
        button.clicked.connect(connection)
        return button

    def create_text_edit(self):
        """Create a styled text edit widget."""
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier", 12))
        return text_edit

    def create_fingerprint(self):
        """Create a new fingerprint using worker thread."""
        if self.worker and self.worker.isRunning():
            self.show_warning(
                "Operation in Progress", "Please wait for current operation to complete"
            )
            return

        self.scan_progress.setVisible(True)
        self.scan_progress.setRange(0, 0)  # Indeterminate progress
        self.update_status("Creating fingerprint...")

        self.worker = FingerprintWorker(hash_sensitive=True)
        self.worker.finished.connect(self.on_fingerprint_created)
        self.worker.error.connect(self.on_fingerprint_error)
        self.worker.progress.connect(self.on_fingerprint_progress)
        self.worker.start()

    def on_fingerprint_created(self, fingerprint):
        """Handle successful fingerprint creation."""
        self.current_fingerprint = fingerprint
        save_fingerprint(self.current_fingerprint, "fingerprint_baseline.json")
        self.scan_result.setText(json.dumps(self.current_fingerprint, indent=2))
        self.scan_progress.setVisible(False)
        self.scan_status.setText("")
        self.update_status("Fingerprint created and saved", 5000)

        if self.auto_export_checkbox.isChecked():
            self.export_fingerprint()

        # If this was a scheduled scan, chain the comparison now that
        # creation is complete (avoids the previous fixed-timer race).
        if getattr(self, "_pending_scheduled_compare", False):
            self._pending_scheduled_compare = False
            self.compare_fingerprints()

    def on_fingerprint_error(self, error):
        """Handle fingerprint creation error."""
        self.scan_progress.setVisible(False)
        self.scan_status.setText("")
        self.show_error("Failed to create fingerprint", error)

    def on_fingerprint_progress(self, message):
        """Update progress message."""
        self.scan_status.setText(message)

    def compare_fingerprints(self):
        """Compare current system with baseline."""
        if self.worker and self.worker.isRunning():
            self.show_warning(
                "Operation in Progress", "Please wait for current operation to complete"
            )
            return

        try:
            self.baseline_fingerprint = load_fingerprint("fingerprint_baseline.json")
            if not self.baseline_fingerprint:
                raise FileNotFoundError("No baseline fingerprint found")

            self.compare_progress.setVisible(True)
            self.compare_progress.setRange(0, 0)
            self.update_status("Comparing fingerprints...")

            self.worker = ComparisonWorker(
                self.baseline_fingerprint, hash_sensitive=True
            )
            self.worker.finished.connect(self.on_comparison_complete)
            self.worker.error.connect(self.on_comparison_error)
            self.worker.progress.connect(self.on_comparison_progress)
            self.worker.start()

        except Exception as e:
            self.show_warning("Failed to load baseline", str(e))

    def on_comparison_complete(self, differences):
        """Handle successful comparison."""
        self.compare_progress.setVisible(False)
        self.compare_status.setText("")

        summary = differences["summary"]
        if summary["total_changes"] == 0:
            self.compare_result.setText("No differences found.")
            self.update_status("Comparison complete - no differences", 5000)
        else:
            result_text = "Comparison Summary:\n"
            result_text += f"Total Changes: {summary['total_changes']}\n"
            result_text += f"Critical: {summary['critical']}\n"
            result_text += f"High: {summary['high']}\n"
            result_text += f"Medium: {summary['medium']}\n"
            result_text += f"Low: {summary['low']}\n\n"
            result_text += json.dumps(differences, indent=2)

            self.compare_result.setText(result_text)
            self.update_status("Comparison complete - differences found", 5000)

        if self.auto_export_checkbox.isChecked():
            self.export_comparison()

    def on_comparison_error(self, error):
        """Handle comparison error."""
        self.compare_progress.setVisible(False)
        self.compare_status.setText("")
        self.show_error("Comparison Failed", error)

    def on_comparison_progress(self, message):
        """Update comparison progress message."""
        self.compare_status.setText(message)

    def schedule_scan(self):
        """Schedule a daily scan."""
        try:
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.scheduled_scan)
            self.timer.start(24 * 60 * 60 * 1000)  # 24 hours
            next_scan = datetime.now() + timedelta(days=1)
            next_scan = next_scan.replace(hour=0, minute=0, second=0, microsecond=0)
            self.schedule_label.setText(
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
            self.schedule_label.setText("Next scheduled scan: Not set")
            self.update_status("Scheduled scan cancelled", 5000)
        else:
            self.show_info("No scheduled scan to cancel")

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
        if not self.compare_result.toPlainText():
            self.show_warning("No Comparison", "Run a comparison first")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Comparison", "", "JSON Files (*.json);;HTML Files (*.html)"
        )
        if filename:
            try:
                if filename.endswith(".html"):
                    # Export as HTML would require the comparison result
                    self.show_info(
                        "HTML export requires running comparison through CLI"
                    )
                else:
                    with open(filename, "w") as f:
                        f.write(self.compare_result.toPlainText())
                self.update_status(f"Comparison exported to {filename}", 5000)
            except Exception as e:
                self.show_error("Export Failed", str(e))

    def on_theme_changed(self, theme):
        """Handle theme change."""
        self.theme = theme.lower()
        self.apply_theme()

    def choose_custom_color(self, color_name):
        """Choose custom color."""
        color = QColorDialog.getColor()
        if color.isValid():
            self.custom_colors[color_name] = color.name()
            self.custom_color_buttons[color_name].setStyleSheet(
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
        self.settings.setValue("auto_export", self.auto_export_checkbox.isChecked())
        self.settings.setValue("theme", self.theme)
        for color_name, color_value in self.custom_colors.items():
            self.settings.setValue(f"custom_{color_name}", color_value)
        self.update_status("Settings saved", 5000)

    def load_settings(self):
        """Load application settings."""
        self.auto_export_checkbox.setChecked(
            self.settings.value("auto_export", False, type=bool)
        )
        self.theme = self.settings.value("theme", "light")
        self.theme_combo.setCurrentText(self.theme.capitalize())
        for color_name in self.custom_colors:
            self.custom_colors[color_name] = self.settings.value(
                f"custom_{color_name}", self.custom_colors[color_name]
            )
            self.custom_color_buttons[color_name].setStyleSheet(
                f"background-color: {self.custom_colors[color_name]};"
            )

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
