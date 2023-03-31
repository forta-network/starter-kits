from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType


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

        finding = Finding({
            'name': 'Positive Reputation',
            'description': f'{address} has positive reputation',
            'alert_id': 'POSITIVE-REPUTATION-1',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'labels': labels
        })
        return finding
