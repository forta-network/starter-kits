from forta_agent import Finding, FindingType, FindingSeverity


class PositiveReputationFindings:

    @staticmethod
    def positive_reputation(address: str) -> Finding:
        finding = Finding({
            'name': 'Positive Reputation',
            'description': f'{address} has positive reputation',
            'alert_id': 'POSITIVE-REPUTATION-1',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
        })
        return finding
