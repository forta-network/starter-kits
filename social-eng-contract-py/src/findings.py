from forta_agent import Finding, FindingSeverity, FindingType, EntityType


class SocialEngContractFindings:

    @staticmethod
    def social_eng_contract_creation(from_address: str, contract_address: str, impersonated_contract: str, anomaly_score: float) -> Finding:
        labels = [{"entity": from_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.6},  # low
                  {"entity": contract_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker_contract",
                   "confidence": 0.6},  # low
                  {"entity": impersonated_contract,
                   "entity_type": EntityType.Address,
                   "label": "victim",
                   "confidence": 0.6}]  # low

        return Finding({
            'name': 'A social engineering contract was created.',
            'description': f'{from_address} created contract {contract_address} impersonating {impersonated_contract}',
            'alert_id': 'SOCIAL-ENG-CONTRACT-CREATION',
            'type': FindingType.Exploit,
            'severity': FindingSeverity.High,
            'metadata': {"anomaly_score": anomaly_score, "impersonated_contract": impersonated_contract},
            'labels': labels
        })

