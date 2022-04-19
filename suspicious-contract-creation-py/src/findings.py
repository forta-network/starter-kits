from forta_agent import Finding, FindingType, FindingSeverity


class SuspiciousContractFindings:

    @staticmethod
    def suspicious_contract_creation_tornado_cash(from_address: str, contract_address: str, contained_addresses: set) -> Finding:
        return Finding({
            'name': 'Suspicious Contract Creation by Tornado Cash funded account',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'metadata': {  
                'addresses_contained_in_created_contract': str(contained_addresses)
            }
        })

    @staticmethod
    def suspicious_contract_creation(from_address: str, contract_address: str, contained_addresses: set) -> Finding:
        return Finding({
            'name': 'Suspicious Contract Creation',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'SUSPICIOUS-CONTRACT-CREATION',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Low,
            'metadata': {  
                'addresses_contained_in_created_contract': str(contained_addresses)
            }
        })