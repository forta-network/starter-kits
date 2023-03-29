from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label


class MEVAccountFinding:

    @staticmethod
    def MEVAccount(address: str, transfer_event_count: int, unique_token_count: int, unique_contract_address_count: int, chain_id: int) -> Finding:

        labels = []
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "benign",
            'entity': address,
            'confidence': 0.80,
            'remove': "false",
            'metadata': {
                'alert_id': 'MEV-ACCOUNT',
                'chain_id': chain_id
            }
        }))

        finding = Finding({
            'name': 'MEV Account Identified',
            'description': f'{address} seems to be engaged in MEV activity',
            'alert_id': 'MEV-ACCOUNT',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {'transfer_event_count': transfer_event_count, 'unique_token_count': unique_token_count, 'unique_contract_address_count': unique_contract_address_count},
            'labels': labels
        })
        return finding
