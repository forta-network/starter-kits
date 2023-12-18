from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f"


class PositiveReputationFindings:

    @staticmethod
    def positive_reputation(address: str, chain_id: int) -> Finding:
        labels = []
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "benign",
            'entity': address,
            'confidence': 0.80,
            'metadata': {
                'alert_id': 'POSITIVE-REPUTATION-1',
                'chain_id': chain_id
            }
        }))

        metadata = {}

        if chain_id not in [43114, 10, 250]:
            metadata['anomaly_score'] = calculate_alert_rate(
                chain_id,
                BOT_ID,
                'POSITIVE-REPUTATION-1',
                ScanCountType.TX_COUNT)

        finding = Finding({
            'name': 'Positive Reputation',
            'description': f'{address} has positive reputation',
            'alert_id': 'POSITIVE-REPUTATION-1',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'labels': labels,
            'metadata': metadata
        })
        return finding

    @staticmethod
    def positive_reputation_by_age(address: str, chain_id: int) -> Finding:
        labels = []
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "benign",
            'entity': address,
            'confidence': 0.80,
            'metadata': {
                'alert_id': 'POSITIVE-REPUTATION-2',
                'chain_id': chain_id
            }
        }))

        metadata = {}

        if chain_id not in [43114, 10, 250]:
            metadata['anomaly_score'] = calculate_alert_rate(
                chain_id,
                BOT_ID,
                'POSITIVE-REPUTATION-2',
                ScanCountType.TX_COUNT)

        finding = Finding({
            'name': 'Positive Reputation',
            'description': f'{address} has positive reputation',
            'alert_id': 'POSITIVE-REPUTATION-2',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'labels': labels,
            'metadata': metadata
        })
        return finding
    
    @staticmethod
    def positive_reputation_by_contract_deployment(address: str, chain_id: int) -> Finding:
        labels = []
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "benign",
            'entity': address,
            'confidence': 0.80,
            'metadata': {
                'alert_id': 'POSITIVE-REPUTATION-3',
                'chain_id': chain_id
            }
        }))

        metadata = {}

        if chain_id not in [43114, 10, 250]:
            metadata['anomaly_score'] = calculate_alert_rate(
                chain_id,
                BOT_ID,
                'POSITIVE-REPUTATION-3',
                ScanCountType.TX_COUNT)

        finding = Finding({
            'name': 'Positive Reputation',
            'description': f'{address} has positive reputation',
            'alert_id': 'POSITIVE-REPUTATION-3',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'labels': labels,
            'metadata': metadata
        })
        return finding
