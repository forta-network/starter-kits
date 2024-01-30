from typing import TypedDict

class LabelSourceBot(TypedDict):
    id: str
    image: str
    image_hash: str
    manifest: str

class LabelSource(TypedDict):
    id: str
    alert_hash: str
    alert_id: str
    chain_id: str
    bot: LabelSourceBot
