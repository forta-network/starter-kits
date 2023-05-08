from forta_agent import Finding, FindingType, FindingSeverity, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

from src.keys import BOT_ID


class MaliciousAccountFundingFinding:
    @staticmethod
    def funding(
        tx_hash, to_address: str, from_address: str, from_tag: str, chain_id: int
    ) -> Finding:
        labels = [
            {
                "entity": tx_hash,
                "entity_type": EntityType.Transaction,
                "label": "attacker",
                "confidence": 1,
            }
        ]

        finding = Finding(
            {
                "name": "Known Malicious Account Funding",
                "description": f"{to_address} received funds from known malicious account",
                "alert_id": "MALICIOUS-ACCOUNT-FUNDING",
                "type": FindingType.Suspicious,
                "severity": FindingSeverity.High,
                "metadata": {
                    "from_address": from_address,
                    "from_tag": from_tag,
                    "anomaly_score": calculate_alert_rate(
                        chain_id,
                        BOT_ID,
                        "MALICIOUS-ACCOUNT-FUNDING",
                        ScanCountType.TRANSFER_COUNT,
                    ),
                },
                "labels": labels,
            }
        )

        return finding
