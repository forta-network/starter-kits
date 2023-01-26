from forta_agent import Finding, FindingSeverity, FindingType, EntityType


class UnverifiedCodeContractFindings:

    @staticmethod
    def unverified_code(from_address: str, contract_address: str, anomaly_score: float, contained_addresses: set) -> Finding:

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
            'name': 'Contract with unverified code was created',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'UNVERIFIED-CODE-CONTRACT-CREATION',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Medium,
            'metadata': metadata,
            'labels': labels
        })
