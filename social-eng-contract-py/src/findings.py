from forta_agent import Finding, FindingSeverity, FindingType


class SocialEngContractFindings:

    @staticmethod
    def social_eng_contract_creation(from_address: str, contract_address: str, impersonated_contract: str) -> Finding:
        return Finding({
            'name': 'A social engineering contract was created.',
            'description': f'{from_address} created contract {contract_address} impersonating {impersonated_contract}',
            'alert_id': 'SOCIAL-ENG-CONTRACT-CREATION',
            'type': FindingType.Exploit,
            'severity': FindingSeverity.High,
            'metadata': {"impersonated_contract": impersonated_contract}
        })

