from forta_agent import Finding, FindingType, FindingSeverity


class FundingTornadoCashFindings:

    @staticmethod
    def funding_tornado_cash(to_address: str) -> Finding:
        return Finding({
            'name': 'Tornado Cash Funding',
            'description': f'{to_address} received initial funds from Tornado Cash',
            'alert_id': 'FUNDING-TORNADO-CASH',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Low,
        })
