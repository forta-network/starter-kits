from forta_bot import Finding, FindingSeverity, FindingType, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType
import hashlib
BOT_ID = "0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3"


class UnverifiedCodeContractFindings:

    @staticmethod
    def unverified_code(from_address: str, contract_address: str, chain_id: int, contained_addresses: set, transaction_hash: str) -> Finding:

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
        metadata = {**addresses}

        if chain_id not in [43114, 10, 250]:
            score = calculate_alert_rate(
                chain_id,
                BOT_ID,
                'UNVERIFIED-CODE-CONTRACT-CREATION',
                ScanCountType.CONTRACT_CREATION_COUNT)
            metadata['anomaly_score'] = str(score)

        unique_key = hashlib.sha256(f'{from_address},{contract_address}'.encode()).hexdigest()

        unique_key = hashlib.sha256(f'{from_address},{contract_address}'.encode()).hexdigest()

        return Finding({
            'name': 'Contract with unverified code was created',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'UNVERIFIED-CODE-CONTRACT-CREATION',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Medium,
            'metadata': metadata,
            'source': {
                'chains': [{'chainId': chain_id}],
                'transactions': [{'chainId': chain_id, 'hash': transaction_hash}]
            },
            'labels': labels,
            'unique_key': unique_key
        })
