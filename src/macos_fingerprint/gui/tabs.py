"""
Individual tab widgets for the GUI.
"""

from datetime import datetime, timedelta

from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QPushButton,
    QTextEdit,
    QLabel,
    QHBoxLayout,
    QStyle,
    QProgressBar,
    QCheckBox,
    QComboBox,
)
from PyQt5.QtGui import QFont


def create_button(parent, text, icon, connection):
    """Create a styled button."""
    button = QPushButton(text)
    button.setIcon(parent.style().standardIcon(icon))
    button.setFont(QFont("Arial", 14))
    button.setMinimumHeight(50)
    button.clicked.connect(connection)
    return button


def create_text_edit():
    """Create a styled read-only text edit widget."""
    text_edit = QTextEdit()
    text_edit.setReadOnly(True)
    text_edit.setFont(QFont("Courier", 12))
    return text_edit


class ScanTab(QWidget):
    """Scan / create fingerprint tab."""

    def __init__(self, parent_app):
        super().__init__()
        self.app = parent_app
        layout = QVBoxLayout(self)

        self.scan_button = create_button(
            self, "Create New Fingerprint", QStyle.SP_BrowserReload,
            self.app.create_fingerprint,
        )
        layout.addWidget(self.scan_button)
        self.app._action_buttons.append(self.scan_button)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.status = QLabel("")
        self.status.setFont(QFont("Arial", 10))
        layout.addWidget(self.status)

        self.result = create_text_edit()
        layout.addWidget(self.result)

        self.export_button = create_button(
            self, "Export Fingerprint", QStyle.SP_DialogSaveButton,
            self.app.export_fingerprint,
        )
        layout.addWidget(self.export_button)
        self.app._action_buttons.append(self.export_button)


class CompareTab(QWidget):
    """Compare fingerprints tab."""

    def __init__(self, parent_app):
        super().__init__()
        self.app = parent_app
        layout = QVBoxLayout(self)

        # Baseline selection row
        baseline_row = QHBoxLayout()
        self.baseline_label = QLabel("Baseline: (default)")
        self.baseline_label.setFont(QFont("Arial", 10))
        baseline_row.addWidget(self.baseline_label, 1)

        self.load_baseline_button = QPushButton("Load Baseline...")
        self.load_baseline_button.setIcon(
            self.style().standardIcon(QStyle.SP_DialogOpenButton)
        )
        self.load_baseline_button.clicked.connect(self.app.load_baseline_file)
        baseline_row.addWidget(self.load_baseline_button)
        self.app._action_buttons.append(self.load_baseline_button)

        layout.addLayout(baseline_row)

        self.compare_button = create_button(
            self, "Compare with Baseline", QStyle.SP_FileDialogContentsView,
            self.app.compare_fingerprints,
        )
        layout.addWidget(self.compare_button)
        self.app._action_buttons.append(self.compare_button)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.status = QLabel("")
        self.status.setFont(QFont("Arial", 10))
        layout.addWidget(self.status)

        self.result = create_text_edit()
        layout.addWidget(self.result)

        self.export_button = create_button(
            self, "Export Comparison", QStyle.SP_DialogSaveButton,
            self.app.export_comparison,
        )
        layout.addWidget(self.export_button)
        self.app._action_buttons.append(self.export_button)


class ScheduleTab(QWidget):
    """Schedule tab."""

    def __init__(self, parent_app):
        super().__init__()
        self.app = parent_app
        layout = QVBoxLayout(self)

        self.schedule_label = QLabel("Next scheduled scan: Not set")
        self.schedule_label.setFont(QFont("Arial", 12))
        layout.addWidget(self.schedule_label)

        schedule_button = create_button(
            self, "Schedule Daily Scan", QStyle.SP_BrowserReload,
            self.app.schedule_scan,
        )
        layout.addWidget(schedule_button)
        self.app._action_buttons.append(schedule_button)

        cancel_button = create_button(
            self, "Cancel Scheduled Scan", QStyle.SP_BrowserStop,
            self.app.cancel_scheduled_scan,
        )
        layout.addWidget(cancel_button)

        layout.addStretch()


class SettingsTab(QWidget):
    """Settings tab."""

    def __init__(self, parent_app):
        super().__init__()
        self.app = parent_app
        layout = QVBoxLayout(self)

        self.auto_export_checkbox = QCheckBox("Auto-export results")
        layout.addWidget(self.auto_export_checkbox)

        theme_label = QLabel("Theme:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark", "Custom"])
        self.theme_combo.setCurrentText(self.app.theme.capitalize())
        self.theme_combo.currentTextChanged.connect(self.app.on_theme_changed)
        layout.addWidget(theme_label)
        layout.addWidget(self.theme_combo)

        self.custom_color_buttons = {}
        for color_name in ["background", "text", "button"]:
            button = QPushButton(f"Choose {color_name.capitalize()} Color")
            button.clicked.connect(
                lambda _, cn=color_name: self.app.choose_custom_color(cn)
            )
            layout.addWidget(button)
            self.custom_color_buttons[color_name] = button

        save_settings_button = create_button(
            self, "Save Settings", QStyle.SP_DialogSaveButton,
            self.app.save_settings,
        )
        layout.addWidget(save_settings_button)

        layout.addStretch()
