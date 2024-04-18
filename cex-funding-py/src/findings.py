from bot_alert_rate import calculate_alert_rate, ScanCountType
from forta_bot_sdk import Finding, FindingSeverity, FindingType, EntityType, Label

# Prod
# BOT_ID = "0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb"
# Beta
BOT_ID = "0x31edad924e47947521f90b6e4a4075de21fa57e2ebaa751252cb0193bfec2fd7"


class CEXFundingFinding:
    def __init__(self, name: str, to: str, value: int, chain_id: str, txn_hash: str):
        # Set alert_id based on the name
        if name in ["eXch", "ChangeNOW", "FixedFloat"]:
            self.alert_id = "CEX-FUNDING-1"
        else:
            self.alert_id = "CEX-FUNDING-2"
        self.name = name
        self.to = to
        self.value = value
        self.chain_id = chain_id
        self.txn_hash = txn_hash

    def emit_finding(self) -> Finding:
        labels = [Label({
            "entity": self.to,
            "entityType": EntityType.Address,
            "label": "attacker",
            "confidence": 0.1,
        })]  # very low

        metadata = {
            "CEX_name": f"{self.name}",
            "to": f"{self.to}",
            "value": f"{self.value}",
        }

        source = {
            "chains": [{"chainId": self.chain_id}],
            "transactions": [{"chainId": self.chain_id, "hash": self.txn_hash}]
        }

        if self.chain_id not in [43114, 10, 250, 8453]:
            anomaly_score = calculate_alert_rate(
                    self.chain_id,
                    BOT_ID,
                    self.alert_id,
                    ScanCountType.TRANSFER_COUNT,
                )
            metadata["anomaly_score"] = str(anomaly_score)

        return Finding(
            {
                "name": "CEX Funding",
                "description": f"CEX Funding from {self.name} of {self.value} wei to {self.to}",
                "alert_id": self.alert_id,
                "type": FindingType.Suspicious,
                "severity": FindingSeverity.Low,
                "metadata": metadata,
                'source': source,
                "labels": labels,
            }
        )
