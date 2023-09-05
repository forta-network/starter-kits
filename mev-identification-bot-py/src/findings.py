from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b"


class MEVAccountFinding:

    @staticmethod
    def MEVAccount(address: str, transfer_event_count: int, unique_token_count: int, unique_contract_address_count: int, chain_id: int) -> Finding:

        labels = []
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "benign",
            'entity': address,
            'confidence': 0.80,
            'metadata': {
                'alert_id': 'MEV-ACCOUNT',
                'chain_id': chain_id
            }
        }))

        metadata = {'transfer_event_count': transfer_event_count, 'unique_token_count': unique_token_count,
                    'unique_contract_address_count': unique_contract_address_count}

        if chain_id not in [43114, 10, 250]:
            metadata['anomaly_score'] = calculate_alert_rate(
                chain_id,
                BOT_ID,
                'MEV-ACCOUNT',
                ScanCountType.TX_WITH_INPUT_DATA_COUNT)

        finding = Finding({
            'name': 'MEV Account Identified',
            'description': f'{address} seems to be engaged in MEV activity',
            'alert_id': 'MEV-ACCOUNT',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': metadata,
            'labels': labels
        })
        return finding
