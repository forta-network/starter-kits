from forta_agent import Finding, FindingType, FindingSeverity, EntityType
from src.constants import *

class FundingRailgunFindings:

    def funding_railgun(transaction, value, receiver, type, anomaly_score, chain_id):
        if type=="new-eoa":
            finding = Finding({
                'name': 'Railgun Funding',
                'description': f'{receiver} received initial funds from Railgun',
                'alert_id': 'FUNDING-RAILGUN-NEW-ACCOUNT',
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
                'name': 'Railgun Funding',
                'description': f'{transaction.to} received a low amount of funds from Railgun',
                'alert_id': 'FUNDING-RAILGUN-LOW-AMOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Low,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "threshold": f"{RAILGUN_THRESHOLDS[chain_id]} {CURRENCIES[chain_id]}",
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