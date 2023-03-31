from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label


class FundingTornadoCashFindings:

    @staticmethod
    def funding_tornado_cash(to_address: str, type: str, anomaly_score: float, chain_id:int) -> Finding:
        if type=="low":
            labels = [Label({
                'entityType': EntityType.Address,
                'label': "attacker",
                'entity': to_address,
                'confidence': 0.3,
                'metadata': {
                    'alert_id': 'FUNDING-TORNADO-CASH',
                    'chain_id': chain_id
                }
    	    })]

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
            labels = [Label({
                'entityType': EntityType.Address,
                'label': "benign",
                'entity': to_address,
                'confidence': 0.1,
                'metadata': {
                    'alert_id': 'FUNDING-TORNADO-CASH-HIGH',
                    'chain_id': chain_id
                }
    	    })]

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
