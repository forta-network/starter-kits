from forta_agent import Finding, FindingType, FindingSeverity


class MoneyLaunderingTornadoCashFindings:

    @staticmethod
    def possible_money_laundering_tornado_cash(from_address: str, funds_transferred: int) -> Finding:
        return Finding({
            'name': 'Possible Money Laundering With Tornado Cash',
            'description': f'{from_address} potentially engaged in money laundering',
            'alert_id': 'POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'metadata': {
                "total_funds_transferred": str(funds_transferred)
            }
        })
