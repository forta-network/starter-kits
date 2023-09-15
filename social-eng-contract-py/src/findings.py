from forta_agent import Finding, FindingSeverity, FindingType, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0xee275019391109f9ce0de16b78e835c261af1118afeb1a1048a08ccbf67c3ea8"


class SocialEngContractFindings:

    @staticmethod
    def social_eng_contract_creation(from_address: str, contract_address: str, impersonated_contract: str, chain_id: int, alert_id: str) -> Finding:
        labels = [{"entity": from_address,
                   "entityType": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.6},  # low
                  {"entity": contract_address,
                   "entityType": EntityType.Address,
                   "label": "attacker_contract",
                   "confidence": 0.6},  # low
                  {"entity": impersonated_contract,
                   "entityType": EntityType.Address,
                   "label": "victim",
                   "confidence": 0.6}]  # low

        metadata = {"impersonated_contract": impersonated_contract}

        if chain_id not in [43114, 10, 250]:
            metadata['anomaly_score'] = calculate_alert_rate(
                chain_id,
                BOT_ID,
                alert_id,
                ScanCountType.CONTRACT_CREATION_COUNT)

        return Finding({
            'name': 'A social engineering contract was created.',
            'description': f'{from_address} created contract {contract_address} impersonating {impersonated_contract}',
            'alert_id': alert_id,
            'type': FindingType.Exploit,
            'severity': FindingSeverity.High,
            'metadata': metadata,
            'labels': labels
        })
