from forta_bot import Finding, FindingSeverity, FindingType, EntityType
from constants import *

class FundingExchFindings:

    def funding_exch(transaction, type, anomaly_score, chain_id):
        if type=="new-eoa":
            finding = Finding({
                'name': 'eXch Funding',
                'description': f'{transaction.to} received initial funds from eXch',
                'alert_id': 'FUNDING-EXCH-NEW-ACCOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Medium,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "amount_funded": f"{transaction.transaction.value / 1e18} {CURRENCIES[chain_id]}",
                    "receiving_address": f"{transaction.to}",
                    "anomaly_score": anomaly_score
                },
                'source': {
                    'chains': [{'chainId': chain_id}],
                    'transactions': [{'chainId': chain_id, 'hash': transaction.hash}]
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
                'name': 'eXch Funding',
                'description': f'{transaction.to} received a low amount of funds from eXch',
                'alert_id': 'FUNDING-EXCH-LOW-AMOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Low,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "threshold": f"{EXCH_THRESHOLD} {CURRENCIES[chain_id]}",
                    "amount_funded": f"{transaction.transaction.value / 1e18} {CURRENCIES[chain_id]}",
                    "receiving_address": f"{transaction.to}",
                    "anomaly_score": anomaly_score
                },
                'source': {
                    'chains': [{'chainId': chain_id}],
                    'transactions': [{'chainId': chain_id, 'hash': transaction.hash}]
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