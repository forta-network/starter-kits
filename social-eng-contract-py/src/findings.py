from forta_agent import Finding, FindingSeverity, FindingType, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

from src.keys import BOT_ID


class SocialEngContractFindings:

    @staticmethod
    def social_eng_contract_creation(from_address: str, contract_address: str, impersonated_contract: str, chain_id: int) -> Finding:
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

        return Finding({
            'name': 'A social engineering contract was created.',
            'description': f'{from_address} created contract {contract_address} impersonating {impersonated_contract}',
            'alert_id': 'SOCIAL-ENG-CONTRACT-CREATION',
            'type': FindingType.Exploit,
            'severity': FindingSeverity.High,
            'metadata': {"anomaly_score": calculate_alert_rate(
                chain_id,
                BOT_ID,
                "SOCIAL-ENG-CONTRACT-CREATION",
                ScanCountType.CONTRACT_CREATION_COUNT,
            ), "impersonated_contract": impersonated_contract},
            'labels': labels
        })
