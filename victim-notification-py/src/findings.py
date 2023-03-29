from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType


class VictimNotificationFinding:

    @staticmethod
    def Victim(victim_address: str, notifier_address: str, chain_id:int) -> Finding:
        labels = []
        labels.append(Label({
            'entityType': EntityType.Address,
            'label': "benign",
            'entity': victim_address,
            'confidence': 0.80,
            'remove': "false",
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
            'remove': "false",
            'metadata': {
                'alert_id': 'VICTIM-NOTIFICATION-1',
                'chain_id': chain_id
            }
        }))

        finding = Finding({
            'name': 'Victim Notified',
            'description': f'{victim_address} was notified to be a victim by {notifier_address}',
            'alert_id': 'VICTIM-NOTIFICATION-1',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'labels': labels
        })
        return finding
