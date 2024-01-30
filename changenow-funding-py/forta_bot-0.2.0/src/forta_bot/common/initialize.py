
from typing import Callable, Optional, TypedDict
from ..alerts import AlertSubscription


class AlertConfig(TypedDict):
  subscriptions: list[AlertSubscription]
  
class InitializeResponse(TypedDict):
  alert_config: AlertConfig


Initialize = Callable[[], Optional[InitializeResponse]]