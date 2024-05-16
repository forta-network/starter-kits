from forta_bot_sdk import Finding, FindingType, FindingSeverity, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType


class MaliciousAccountFundingFinding:
    @staticmethod
    def funding(
        tx_hash, to_address: str, from_address: str, from_tag: str, chain_id: int, bot_id: str
    ) -> Finding:
        labels = [
            {
                "entity": tx_hash,
                "entity_type": EntityType.Transaction,
                "label": "attacker",
                "confidence": 1,
            }
        ]

        metadata = {
            "from_address": from_address,
            "from_tag": from_tag
        }

        if chain_id not in [43114, 10, 250]:
            metadata['anomaly_score'] = str(calculate_alert_rate(
                chain_id,
                bot_id,
                "MALICIOUS-ACCOUNT-FUNDING",
                ScanCountType.TRANSFER_COUNT,
            ))

        finding = Finding(
            {
                "name": "Known Malicious Account Funding",
                "description": f"{to_address} received funds from known malicious account",
                "alert_id": "MALICIOUS-ACCOUNT-FUNDING",
                "type": FindingType.Suspicious,
                "severity": FindingSeverity.High,
                "metadata": metadata,
                "labels": labels,
                "source": {
                    "chains": [{"chainId": chain_id}],
                    "transactions": [{"chainId": chain_id, "hash": tx_hash}]
                }
            }
        )

        return finding
