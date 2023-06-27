from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0xe04b3fa79bd6bc6168a211bcec5e9ac37d5dd67a41a1884aa6719f8952fbc274"


class VictimNotificationFinding:

    @staticmethod
    def Victim(victim_address: str, notifier_address: str, chain_id: int) -> Finding:
        labels = []
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "benign",
            'entity': victim_address,
            'confidence': 0.80,
            'metadata': {
                'alert_id': 'VICTIM-NOTIFICATION-1',
                'chain_id': chain_id
            }
        }))
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "victim",
            'entity': victim_address,
            'confidence': 0.99,
            'metadata': {
                'alert_id': 'VICTIM-NOTIFICATION-1',
                'chain_id': chain_id
            }
        }))

        metadata = {"anomaly_score": calculate_alert_rate(
            chain_id,
            BOT_ID,
            'VICTIM-NOTIFICATION-1',
            ScanCountType.TX_WITH_INPUT_DATA_COUNT,
        )}

        finding = Finding({
            'name': 'Victim Notified',
            'description': f'{victim_address} was notified to be a victim by {notifier_address}',
            'alert_id': 'VICTIM-NOTIFICATION-1',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'labels': labels,
            'metadata': metadata
        })
        return finding
