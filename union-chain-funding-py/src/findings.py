from forta_agent import Finding, FindingType, FindingSeverity, EntityType
from src.constants import *

class FundingUnionChainFindings:

    def funding_union_chain(transaction, type, anomaly_score, chain_id):
        if type=="new-eoa":
            finding = Finding({
                'name': 'Union Chain Funding',
                'description': f'{transaction.to} received initial funds from Union Chain',
                'alert_id': 'FUNDING-UNION-CHAIN-NEW-ACCOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Medium,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "amount funded": f"{transaction.transaction.value / 1e18} {CURRENCIES[chain_id]}",
                    "receiving address": f"{transaction.to}",
                    "anomaly_score": anomaly_score
                },
                'labels': [
                    {
                        'entityType': EntityType.Address,
                        'entity': transaction.to,
                        'label': "attacker",
                        'confidence': 0.2
                    },
                    {
                        'entityType': EntityType.Transaction,
                        'entity': transaction.transaction.hash,
                        'label': "attacker-funding",
                        'confidence': 0.2
                    },
                ]
            })
        else:
            finding = Finding({
                'name': 'Union Chain Funding',
                'description': f'{transaction.to} received a low amount of funds from Union Chain',
                'alert_id': 'FUNDING-UNION-CHAIN-LOW-AMOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Low,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "threshold": f"{UNION_CHAIN_THRESHOLD} {CURRENCIES[chain_id]}",
                    "amount_funded": f"{transaction.transaction.value / 1e18} {CURRENCIES[chain_id]}",
                    "receiving_address": f"{transaction.to}",
                    "anomaly_score": anomaly_score
                },
                'labels': [
                    {
                        'entityType': EntityType.Address,
                        'entity': transaction.to,
                        'label': "attacker",
                        'confidence': 0.2
                    },
                    {
                        'entityType': EntityType.Transaction,
                        'entity': transaction.transaction.hash,
                        'label': "attacker-funding",
                        'confidence': 0.2
                    },
                ]
            })
        return finding