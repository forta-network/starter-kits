from forta_agent import Finding, FindingType, FindingSeverity, EntityType


class MoneyLaunderingTornadoCashFindings:

    @staticmethod
    def possible_money_laundering_tornado_cash(from_address: str, funds_transferred: int, anomaly_score: float) -> Finding:
        labels = [{"entity": from_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.5}]
        
        return Finding({
            'name': 'Possible Money Laundering With Tornado Cash',
            'description': f'{from_address} potentially engaged in money laundering',
            'alert_id': 'POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'metadata': {
                "anomaly_score": anomaly_score,
                "total_funds_transferred": str(funds_transferred)
            },
            "labels": labels
        })
