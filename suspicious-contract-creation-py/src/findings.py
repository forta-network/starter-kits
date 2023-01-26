from forta_agent import Finding, FindingType, FindingSeverity, EntityType


class SuspiciousContractFindings:

    @staticmethod
    def suspicious_contract_creation_tornado_cash(from_address: str, contract_address: str, contained_addresses: set, anomaly_score: float) -> Finding:
        labels = [{"entity": from_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.3},  # low
                  {"entity": contract_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker_contract",
                   "confidence": 0.3}]  # low

        addresses = {"address_contained_in_created_contract_" + str(i): address for i, address in enumerate(contained_addresses, 1)}
        metadata = {"anomaly_score": anomaly_score, **addresses}

        return Finding({
            'name': 'Suspicious Contract Creation by Tornado Cash funded account',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'metadata': metadata,
            'labels': labels,
        })

    @staticmethod
    def suspicious_contract_creation(from_address: str, contract_address: str, contained_addresses: set, anomaly_score: float) -> Finding:
        labels = [{"entity": from_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.1},  # very low
                  {"entity": contract_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker_contract",
                   "confidence": 0.1}]  # very low

        addresses = {"address_contained_in_created_contract_" + str(i): address for i, address in enumerate(contained_addresses, 1)}
        metadata = {"anomaly_score": anomaly_score, **addresses}

        return Finding({
            'name': 'Suspicious Contract Creation',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'SUSPICIOUS-CONTRACT-CREATION',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Low,
            'metadata': metadata,
            'labels': labels
        })
