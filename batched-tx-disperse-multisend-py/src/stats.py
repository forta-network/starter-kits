"""Statistics on the bot alert rate."""

import collections

# INIT ########################################################################

def init_alert_history(size: int) -> collections.deque:
    """Creates a FIFO of fixed size N to store the alerts for the latest N transactions."""
    return collections.deque(size * [()], size)

# UPDATE ######################################################################

def update_alert_history(fifo: collections.deque, alerts: tuple) -> None:
    """Push"""
    fifo.append(alerts)

# PROCESS #####################################################################

def calculate_alert_rate(fifo: collections.deque, alert: str) -> float:
    """Calculate the alert rate for a given id over the last N transactions."""
    return min(sum([_t.count(alert) for _t in fifo]) / len(fifo), 1.)
