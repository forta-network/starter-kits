from forta_agent import Finding, FindingType, FindingSeverity, EntityType


class FundingTornadoCashFindings:

    @staticmethod
    def funding_tornado_cash(to_address: str, type:str, anomaly_score: float) -> Finding:
        confidence = 0.3 if type == "low" else 0.1

        labels = [{"entity": to_address,
                   "entityType": EntityType.Address,
                   "label": "attacker",
                   "confidence": confidence}]

        if type=="low":
            finding = Finding({
                'name': 'Tornado Cash Funding',
                'description': f'{to_address} received initial funds from Tornado Cash',
                'alert_id': 'FUNDING-TORNADO-CASH',
                'type': FindingType.Suspicious,
                'severity': FindingSeverity.Low,
                'metadata': {'anomaly_score': anomaly_score},
                'labels': labels
            })
        else:
            finding = Finding({
                'name': 'Tornado Cash Funding',
                'description': f'{to_address} received large funds from Tornado Cash',
                'alert_id': 'FUNDING-TORNADO-CASH-HIGH',
                'type': FindingType.Info,
                'severity': FindingSeverity.Info,
                'metadata': {'anomaly_score': anomaly_score},
                'labels': labels
            })
        return finding
