from forta_agent import Finding, FindingType, FindingSeverity, EntityType
from src.constants import *

class FundingSwftSwapFindings:

    def funding_swft_swap(transaction, value, receiver, type, anomaly_score, chain_id):
        if type=="new-eoa":
            finding = Finding({
                'name': 'SWFT Swap Funding',
                'description': f'{receiver} received initial funds from SWFT Swap',
                'alert_id': 'FUNDING-SWFT-SWAP-NEW-ACCOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Medium,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "amount_funded": f"{value} {CURRENCIES[chain_id]}",
                    "receiving_address": f"{receiver}",
                    "anomaly_score": anomaly_score
                },
                'labels': [
                    {
                        'entityType': EntityType.Address,
                        'entity': receiver,
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
                'name': 'SWFT Swap Funding',
                'description': f'{transaction.to} received a low amount of funds from SWFT Swap',
                'alert_id': 'FUNDING-SWFT-SWAP-LOW-AMOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Low,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "threshold": f"{SWFT_SWAP_THRESHOLDS[chain_id]} {CURRENCIES[chain_id]}",
                    "amount_funded": f"{value} {CURRENCIES[chain_id]}",
                    "receiving_address": receiver,
                    "anomaly_score": anomaly_score
                },
                'labels': [
                    {
                        'entityType': EntityType.Address,
                        'entity': receiver,
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