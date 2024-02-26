from forta_bot import Finding, FindingSeverity, FindingType, EntityType
from constants import *

class FundingThorchainFindings:

    def funding_thorchain(transaction, recipient, type, anomaly_score, chain_id):
        if type=="new-eoa":
            finding = Finding({
                'name': 'Thorchain Funding',
                'description': f'{recipient} received initial funds from Thorchain',
                'alert_id': 'FUNDING-THORCHAIN-NEW-ACCOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Medium,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "amount_funded": f"{transaction.transaction.value / 1e18} {CURRENCIES[chain_id]}",
                    "receiving_address": f"{recipient}",
                    "anomaly_score": anomaly_score
                },
                'source': {
                    'chains': [{'chainId': chain_id}],
                    'transactions': [{'chainId': chain_id, 'hash': transaction.hash}]
                },
                'labels': [
                    {
                        'entityType': EntityType.Address,
                        'entity': recipient,
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
                'name': 'Thorchain Funding',
                'description': f'{recipient} received a low amount of funds from Thorchain',
                'alert_id': 'FUNDING-THORCHAIN-LOW-AMOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Low,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "threshold": f"{THORCHAIN_THRESHOLDS[chain_id]} {CURRENCIES[chain_id]}",
                    "amount_funded": f"{transaction.transaction.value / 1e18} {CURRENCIES[chain_id]}",
                    "receiving_address": f"{recipient}",
                    "anomaly_score": anomaly_score
                },
                'source': {
                    'chains': [{'chainId': chain_id}],
                    'transactions': [{'chainId': chain_id, 'hash': transaction.hash}]
                },
                'labels': [
                    {
                        'entityType': EntityType.Address,
                        'entity': recipient,
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