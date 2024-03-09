from forta_bot import Finding, FindingType, FindingSeverity, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0x64df42068faa19d842c8df94156b8ec0f28758d6775ee912b0733c89c57e2486"


class SuspiciousContractFindings:

    @staticmethod
    def suspicious_contract_creation_tornado_cash(from_address: str, contract_address: str, contained_addresses: set, chain_id: int, tx_hash: str) -> Finding:
        labels = [{"entity": from_address,
                   "entityType": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.3},  # low
                  {"entity": contract_address,
                   "entityType": EntityType.Address,
                   "label": "attacker_contract",
                   "confidence": 0.3}]  # low

        addresses = {"address_contained_in_created_contract_" +
                     str(i): address for i, address in enumerate(contained_addresses, 1)}
        metadata = {**addresses}

        if chain_id not in [43114, 10, 250, 8453]:
            metadata['anomaly_score'] = str(calculate_alert_rate(
                chain_id,
                BOT_ID,
                'SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH',
                ScanCountType.CONTRACT_CREATION_COUNT))

        return Finding({
            'name': 'Suspicious Contract Creation by Tornado Cash funded account',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'metadata': metadata,
            'labels': labels,
            'source': {
                'chains': [{'chainId': chain_id}],
                'transactions': [{'chainId': chain_id, 'hash': tx_hash}]
            }
        })

    @staticmethod
    def suspicious_contract_creation(from_address: str, contract_address: str, contained_addresses: set, chain_id: int, tx_hash: str) -> Finding:
        labels = [{"entity": from_address,
                   "entityType": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.1},  # very low
                  {"entity": contract_address,
                   "entityType": EntityType.Address,
                   "label": "attacker_contract",
                   "confidence": 0.1}]  # very low

        addresses = {"address_contained_in_created_contract_" +
                     str(i): address for i, address in enumerate(contained_addresses, 1)}

        metadata = {**addresses}

        if chain_id not in [43114, 10, 250, 8453]:
            metadata['anomaly_score'] = str(calculate_alert_rate(
                chain_id,
                BOT_ID,
                'SUSPICIOUS-CONTRACT-CREATION',
                ScanCountType.CONTRACT_CREATION_COUNT))

        return Finding({
            'name': 'Suspicious Contract Creation',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'SUSPICIOUS-CONTRACT-CREATION',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Low,
            'metadata': metadata,
            'labels': labels,
            'source': {
                'chains': [{'chainId': chain_id}],
                'transactions': [{'chainId': chain_id, 'hash': tx_hash}]
            }
        })
