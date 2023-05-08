from forta_agent import Finding, FindingSeverity, FindingType, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

from src.keys import BOT_ID


class UnverifiedCodeContractFindings:

    @staticmethod
    def unverified_code(from_address: str, contract_address: str, chain_id: int, contained_addresses: set) -> Finding:

        labels = [{"entity": from_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.3},  # low
                  {"entity": contract_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker_contract",
                   "confidence": 0.3}]  # low

        addresses = {"address_contained_in_created_contract_" +
                     str(i): address for i, address in enumerate(contained_addresses, 1)}
        metadata = {"anomaly_score": calculate_alert_rate(
            chain_id,
            BOT_ID,
            'UNVERIFIED-CODE-CONTRACT-CREATION',
            ScanCountType.CONTRACT_CREATION_COUNT,
        ), **addresses}

        return Finding({
            'name': 'Contract with unverified code was created',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'UNVERIFIED-CODE-CONTRACT-CREATION',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Medium,
            'metadata': metadata,
            'labels': labels
        })
