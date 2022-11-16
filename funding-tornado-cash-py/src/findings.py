from forta_agent import Finding, FindingType, FindingSeverity


class FundingTornadoCashFindings:

    @staticmethod
    def funding_tornado_cash(to_address: str, type:str) -> Finding:
        if type=="low":
            finding = Finding({
                'name': 'Tornado Cash Funding',
                'description': f'{to_address} received initial funds from Tornado Cash',
                'alert_id': 'FUNDING-TORNADO-CASH',
                'type': FindingType.Suspicious,
                'severity': FindingSeverity.Low,
            })
        else:
            finding = Finding({
                'name': 'Tornado Cash Funding',
                'description': f'{to_address} received large funds from Tornado Cash',
                'alert_id': 'FUNDING-TORNADO-CASH-HIGH',
                'type': FindingType.Info,
                'severity': FindingSeverity.Info,
            })
        return finding
