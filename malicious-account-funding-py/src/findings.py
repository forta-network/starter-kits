from forta_agent import Finding, FindingType, FindingSeverity, EntityType


class MaliciousAccountFundingFinding:
    @staticmethod
    def funding(
        tx_hash, to_address: str, from_address: str, from_tag: str, anomaly_score: float
    ) -> Finding:
        labels = [
            {
                "entity": tx_hash,
                "entity_type": EntityType.Transaction,
                "label": "malicious-funding",
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
                    "anomaly_score": anomaly_score,
                },
                "labels": labels,
            }
        )

        return finding
