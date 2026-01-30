"""
Fingerprint comparison with diff-style output and severity classification.
"""

import json
from typing import Dict, Any, List
from enum import Enum
from datetime import datetime


class ChangeSeverity(Enum):
    """Severity levels for detected changes."""

    CRITICAL = "critical"  # Security-related changes
    HIGH = "high"  # System-level changes
    MEDIUM = "medium"  # Application or configuration changes
    LOW = "low"  # Minor changes


class ChangeType(Enum):
    """Types of changes detected."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


def classify_severity(collector_name: str, change_type: ChangeType) -> ChangeSeverity:
    """
    Classify the severity of a change based on collector and change type.

    Args:
        collector_name: Name of the collector
        change_type: Type of change

    Returns:
        ChangeSeverity level
    """
    # Critical changes
    critical_collectors = [
        "SecuritySettingsCollector",
        "GatekeeperCollector",
        "SSHConfigCollector",
    ]

    # High severity changes
    high_collectors = [
        "KernelExtensionsCollector",
        "LaunchAgentsCollector",
        "UserAccountsCollector",
        "NetworkConfigCollector",
    ]

    if collector_name in critical_collectors:
        return ChangeSeverity.CRITICAL
    elif collector_name in high_collectors:
        return ChangeSeverity.HIGH
    elif change_type == ChangeType.REMOVED:
        return ChangeSeverity.MEDIUM
    else:
        return ChangeSeverity.LOW


def compare_lists(baseline: List, current: List) -> Dict[str, List]:
    """
    Compare two lists and return added/removed items.

    Args:
        baseline: Baseline list
        current: Current list

    Returns:
        Dictionary with 'added' and 'removed' keys
    """
    baseline_set = set(baseline) if baseline else set()
    current_set = set(current) if current else set()

    added = list(current_set - baseline_set)
    removed = list(baseline_set - current_set)

    return {"added": sorted(added), "removed": sorted(removed)}


def compare_dicts(baseline: Dict, current: Dict) -> Dict[str, Any]:
    """
    Compare two dictionaries recursively.

    Args:
        baseline: Baseline dictionary
        current: Current dictionary

    Returns:
        Dictionary with changes
    """
    changes = {}

    all_keys = set(baseline.keys()) | set(current.keys())

    for key in all_keys:
        if key not in baseline:
            changes[key] = {"type": "added", "value": current[key]}
        elif key not in current:
            changes[key] = {"type": "removed", "value": baseline[key]}
        elif baseline[key] != current[key]:
            # Handle different types
            if isinstance(baseline[key], list) and isinstance(current[key], list):
                list_diff = compare_lists(baseline[key], current[key])
                if list_diff["added"] or list_diff["removed"]:
                    changes[key] = {
                        "type": "modified",
                        "added": list_diff["added"],
                        "removed": list_diff["removed"],
                    }
            elif isinstance(baseline[key], dict) and isinstance(current[key], dict):
                dict_diff = compare_dicts(baseline[key], current[key])
                if dict_diff:
                    changes[key] = {"type": "modified", "changes": dict_diff}
            else:
                changes[key] = {
                    "type": "modified",
                    "baseline": baseline[key],
                    "current": current[key],
                }

    return changes


def compare_fingerprints(
    baseline: Dict[str, Any], current: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Compare two fingerprints and return detailed differences.

    Args:
        baseline: Baseline fingerprint
        current: Current fingerprint

    Returns:
        Dictionary containing comparison results with severity classification
    """
    differences = {
        "timestamp": datetime.now().isoformat(),
        "baseline_timestamp": baseline.get("timestamp", "unknown"),
        "current_timestamp": current.get("timestamp", "unknown"),
        "summary": {
            "total_changes": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "changes": {},
    }

    baseline_collectors = baseline.get("collectors", {})
    current_collectors = current.get("collectors", {})

    all_collectors = set(baseline_collectors.keys()) | set(current_collectors.keys())

    for collector in all_collectors:
        if collector not in baseline_collectors:
            severity = ChangeSeverity.LOW
            differences["changes"][collector] = {
                "severity": severity.value,
                "type": "collector_added",
                "data": current_collectors[collector],
            }
            differences["summary"][severity.value] += 1
            differences["summary"]["total_changes"] += 1
        elif collector not in current_collectors:
            severity = ChangeSeverity.MEDIUM
            differences["changes"][collector] = {
                "severity": severity.value,
                "type": "collector_removed",
                "data": baseline_collectors[collector],
            }
            differences["summary"][severity.value] += 1
            differences["summary"]["total_changes"] += 1
        else:
            baseline_data = baseline_collectors[collector]
            current_data = current_collectors[collector]

            if baseline_data != current_data:
                # Compare the data
                if isinstance(baseline_data, list) and isinstance(current_data, list):
                    diff = compare_lists(baseline_data, current_data)
                    if diff["added"] or diff["removed"]:
                        # Determine severity
                        change_type = ChangeType.MODIFIED
                        severity = classify_severity(collector, change_type)

                        differences["changes"][collector] = {
                            "severity": severity.value,
                            "type": "modified",
                            "added": diff["added"],
                            "removed": diff["removed"],
                        }
                        differences["summary"][severity.value] += 1
                        differences["summary"]["total_changes"] += 1
                elif isinstance(baseline_data, dict) and isinstance(current_data, dict):
                    diff = compare_dicts(baseline_data, current_data)
                    if diff:
                        severity = classify_severity(collector, ChangeType.MODIFIED)

                        differences["changes"][collector] = {
                            "severity": severity.value,
                            "type": "modified",
                            "changes": diff,
                        }
                        differences["summary"][severity.value] += 1
                        differences["summary"]["total_changes"] += 1
                else:
                    severity = classify_severity(collector, ChangeType.MODIFIED)

                    differences["changes"][collector] = {
                        "severity": severity.value,
                        "type": "modified",
                        "baseline": baseline_data,
                        "current": current_data,
                    }
                    differences["summary"][severity.value] += 1
                    differences["summary"]["total_changes"] += 1

    return differences


def export_comparison_html(differences: Dict[str, Any], filename: str) -> bool:
    """
    Export comparison results as HTML.

    Args:
        differences: Comparison results
        filename: Output filename

    Returns:
        True if successful, False otherwise
    """
    try:
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>MacBook Fingerprint Comparison</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{ color: #333; }}
        .summary {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .change {{
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 4px solid #ccc;
        }}
        .critical {{ border-left-color: #d32f2f; }}
        .high {{ border-left-color: #f57c00; }}
        .medium {{ border-left-color: #fbc02d; }}
        .low {{ border-left-color: #388e3c; }}
        .added {{ color: #388e3c; }}
        .removed {{ color: #d32f2f; }}
        code {{
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Courier New', monospace;
        }}
        pre {{
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <h1>MacBook Fingerprint Comparison</h1>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Baseline:</strong> {differences['baseline_timestamp']}</p>
        <p><strong>Current:</strong> {differences['current_timestamp']}</p>
        <p><strong>Total Changes:</strong> {differences['summary']['total_changes']}</p>
        <p><strong>Critical:</strong> {differences['summary']['critical']} |
           <strong>High:</strong> {differences['summary']['high']} |
           <strong>Medium:</strong> {differences['summary']['medium']} |
           <strong>Low:</strong> {differences['summary']['low']}</p>
    </div>

    <h2>Changes</h2>
"""

        for collector, change in differences["changes"].items():
            severity = change["severity"]
            html += f"""
    <div class="change {severity}">
        <h3>{collector} <span style="color: #888; font-size: 0.8em;">({severity})</span></h3>
"""

            if "added" in change:
                html += f"""
        <p><strong class="added">Added ({len(change['added'])}):</strong></p>
        <pre>{json.dumps(change['added'], indent=2)}</pre>
"""

            if "removed" in change:
                html += f"""
        <p><strong class="removed">Removed ({len(change['removed'])}):</strong></p>
        <pre>{json.dumps(change['removed'], indent=2)}</pre>
"""

            if "changes" in change:
                html += f"""
        <p><strong>Changes:</strong></p>
        <pre>{json.dumps(change['changes'], indent=2)}</pre>
"""

            html += """
    </div>
"""

        html += """
</body>
</html>
"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

        return True
    except Exception as e:
        print(f"Error exporting HTML: {e}")
        return False


def export_comparison_json(differences: Dict[str, Any], filename: str) -> bool:
    """
    Export comparison results as JSON.

    Args:
        differences: Comparison results
        filename: Output filename

    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(differences, f, indent=2)
        return True
    except Exception as e:
        print(f"Error exporting JSON: {e}")
        return False
