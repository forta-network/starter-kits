from forta_agent import Finding, FindingType, FindingSeverity


class MaliciousAccountFundingFinding:

    @staticmethod
    def funding(to_address: str, from_address: str, from_tag: str) -> Finding:
        finding = Finding({
            'name': 'Known Malicious Account Funding',
            'description': f'{to_address} received funds from known malicious account',
            'alert_id': 'MALICIOUS-ACCOUNT-FUNDING',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'metadata': {'from_address': from_address, 'from_tag': from_tag}
        })
        return finding
