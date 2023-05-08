from forta_agent import Finding, FindingType, FindingSeverity, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

from src.keys import BOT_ID


class SuspiciousContractFindings:

    @staticmethod
    def suspicious_contract_creation_tornado_cash(from_address: str, contract_address: str, contained_addresses: set, chain_id: int) -> Finding:
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
        metadata = {"anomaly_score": calculate_alert_rate(
            chain_id,
            BOT_ID,
            'SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH',
            ScanCountType.CONTRACT_CREATION_COUNT,
        ), **addresses}

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
    def suspicious_contract_creation(from_address: str, contract_address: str, contained_addresses: set, chain_id: int) -> Finding:
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

        metadata = {"anomaly_score": calculate_alert_rate(
            chain_id,
            BOT_ID,
            'SUSPICIOUS-CONTRACT-CREATION',
            ScanCountType.CONTRACT_CREATION_COUNT,
        ), **addresses}

        return Finding({
            'name': 'Suspicious Contract Creation',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'SUSPICIOUS-CONTRACT-CREATION',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Low,
            'metadata': metadata,
            'labels': labels
        })
