from forta_agent import Finding, FindingType, FindingSeverity


class MEVAccountFinding:

    @staticmethod
    def MEVAccount(address: str, transfer_event_count: int, unique_token_count: int, unique_contract_address_count: int) -> Finding:
        finding = Finding({
            'name': 'MEV Account Identified',
            'description': f'{address} seems to be engaged in MEV activity',
            'alert_id': 'MEV-ACCOUNT',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {'transfer_event_count': transfer_event_count, 'unique_token_count': unique_token_count, 'unique_contract_address_count': unique_contract_address_count}
        })
        return finding
