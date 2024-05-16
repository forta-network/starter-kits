from forta_bot_sdk import Finding, FindingSeverity, FindingType, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0x8c75ad9bafaf617333d77757850e173516682456e0d11cd87c5af80e3daa8530"


class SocialEngContractFindings:

    @staticmethod
    def social_eng_address_creation(address: str, is_contract: bool, impersonated_contract: str, from_address: str, chain_id: int, alert_id: str, hash: str) -> Finding:
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

        if chain_id not in [43114, 10, 250, 8453]:
            anomaly_score = calculate_alert_rate(chain_id, BOT_ID, alert_id, ScanCountType.CONTRACT_CREATION_COUNT)
            metadata['anomaly_score'] = str(anomaly_score)

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
            'labels': labels,
            'source': {
                'chains': [{'chainId': chain_id}],
                'transactions': [{'chainId': chain_id, 'hash': hash}]
            }
        })
