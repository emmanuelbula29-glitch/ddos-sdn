

import threading
from queue import Queue

_alert_queue = Queue()
_lock = threading.Lock()
_alerts_history = []


def get_queue():
    """Get the global alert queue instance."""
    return _alert_queue


def add_alert(alert_dict):
    """Add an alert to the queue and history."""
    global _alerts_history
    with _lock:
        _alerts_history.append(alert_dict)
        if len(_alerts_history) > 1000:
            _alerts_history = _alerts_history[-500:]


def get_recent_alerts(count=50):
    """Get the most recent alerts."""
    with _lock:
        return _alerts_history[-count:]


def get_all_alerts():
    """Get all alerts from history."""
    with _lock:
        return list(_alerts_history)


def clear_history():
    """Clear alert history."""
    global _alerts_history
    with _lock:
        _alerts_history = []