from forta_agent import Finding, FindingSeverity, FindingType, EntityType


class CEXFundingFinding:

    @staticmethod
    def cex_funding(name: str, to: str, value: int, anomaly_score: float) -> Finding:

        labels = [{"entity": to,
                   "entity_type": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.1}]  # very low

        return Finding({
                    "name": "CEX Funding",
                    "description": f"CEX Funding from {name} of {value} wei to {to}",
                    "alert_id": "CEX-FUNDING-1",
                    "type": FindingType.Suspicious,
                    "severity": FindingSeverity.Low,
                    "metadata": {"anomaly_score": anomaly_score, "CEX_name": name, "to": to, "value": value},
                    'labels': labels
                })