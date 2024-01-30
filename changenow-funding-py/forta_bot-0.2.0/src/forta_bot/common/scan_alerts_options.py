from typing import TypedDict
from ..alerts import AlertSubscription

class ScanAlertsOptions(TypedDict):
  subscriptions: list[AlertSubscription]