from forta_agent import Finding, FindingSeverity, FindingType


class UnverifiedCodeContractFindings:

    @staticmethod
    def unverified_code(from_address: str, contract_address: str, contained_addresses: set) -> Finding:
        return Finding({
            'name': 'Contract with unverified code was created',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'UNVERIFIED-CODE-CONTRACT-CREATION',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.Medium,
            'metadata': {"address_contained_in_created_contract_" + str(i): address for i, address in enumerate(contained_addresses, 1)}
        })
