from typing import Optional, TypedDict


class AlertSubscription(TypedDict):
  bot_id: str
  alert_id: Optional[str]
  alert_ids: Optional[list[str]]
  chain_id: Optional[int]