from bot_alert_rate import calculate_alert_rate, ScanCountType
from forta_agent import Finding, FindingSeverity, FindingType, EntityType

from src.keys import BOT_ID


class CEXFundingFinding:
    def __init__(self, name: str, to: str, value: int, chain_id: str):
        self.alert_id = "CEX-FUNDING-1"
        self.name = name
        self.to = to
        self.value = value
        self.chain_id = chain_id

    def emit_finding(self) -> Finding:
        labels = [
            {
                "entity": self.to,
                "entity_type": EntityType.Address,
                "label": "attacker",
                "confidence": 0.1,
            }
        ]  # very low

        return Finding(
            {
                "name": "CEX Funding",
                "description": f"CEX Funding from {self.name} of {self.value} wei to {self.to}",
                "alert_id": self.alert_id,
                "type": FindingType.Suspicious,
                "severity": FindingSeverity.Low,
                "metadata": {
                    "anomaly_score": calculate_alert_rate(
                        self.chain_id,
                        BOT_ID,
                        self.alert_id,
                        ScanCountType.TRANSFER_COUNT,
                    ),
                    "CEX_name": self.name,
                    "to": self.to,
                    "value": self.value,
                },
                "labels": labels,
            }
        )
