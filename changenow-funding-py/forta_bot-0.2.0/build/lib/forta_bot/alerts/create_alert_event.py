from typing import Callable
from .alert import Alert
from .alert_event import AlertEvent

CreateAlertEvent = Callable[[Alert], AlertEvent]

def provide_create_alert_event() -> CreateAlertEvent:
  def create_alert_event(alert: Alert) -> AlertEvent:
    return AlertEvent(alert)

  return create_alert_event