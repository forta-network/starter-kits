from forta_agent import Finding, FindingSeverity, FindingType, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0xee275019391109f9ce0de16b78e835c261af1118afeb1a1048a08ccbf67c3ea8"


class SocialEngContractFindings:

    @staticmethod
    def social_eng_address_creation(address: str, is_contract: bool, impersonated_contract: str, from_address: str, chain_id: int, alert_id: str) -> Finding:
        labels = []
        if from_address is not None and from_address != "":
            labels.append({"entity": from_address,
                           "entityType": EntityType.Address,
                           "label": "attacker",
                           "confidence": 0.6})
        labels.append({"entity": address,
                   "entityType": EntityType.Address,
                   "label": "attacker_contract" if is_contract else "attacker",
                   "confidence": 0.6})
        labels.append({"entity": impersonated_contract,
                   "entityType": EntityType.Address,
                   "label": "victim",
                   "confidence": 0.6})  # low

        metadata = {"impersonated_contract": impersonated_contract}

        if chain_id not in [43114, 10, 250]:
            metadata['anomaly_score'] = calculate_alert_rate(
                chain_id,
                BOT_ID,
                alert_id,
                ScanCountType.CONTRACT_CREATION_COUNT)

        description = f'{from_address} created contract {address} impersonating {impersonated_contract}'
        if is_contract:
            description = f'{address} is impersonating {impersonated_contract}'

        return Finding({
            'name': 'A social engineering contract was created.',
            'description': description,
            'alert_id': alert_id,
            'type': FindingType.Exploit,
            'severity': FindingSeverity.High,
            'metadata': metadata,
            'labels': labels
        })
