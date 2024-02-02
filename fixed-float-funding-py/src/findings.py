from forta_agent import Finding, FindingType, FindingSeverity, EntityType
from src.constants import *

class FundingFixedFloatFindings:

    def funding_fixed_float(transaction, type, anomaly_score, chain_id):
        if type=="new-eoa":
            finding = Finding({
                'name': 'Fixed Float Funding',
                'description': f'{transaction.to} received initial funds from Fixed Float',
                'alert_id': 'FUNDING-FIXED-FLOAT-NEW-ACCOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Medium,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "amount_funded": f"{transaction.transaction.value / 10e17} {CURRENCIES[chain_id]}",
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
        else:
            finding = Finding({
                'name': 'Fixed Float Funding',
                'description': f'{transaction.to} received a low amount of funds from Fixed Float',
                'alert_id': 'FUNDING-FIXED-FLOAT-LOW-AMOUNT',
                'type': FindingType.Info,
                'severity': FindingSeverity.Low,
                'protocol': PROTOCOLS[chain_id],
                'addresses': list(transaction.addresses.keys()),
                'metadata': {
                    "threshold": f"{FIXED_FLOAT_THRESHOLD[chain_id]} {CURRENCIES[chain_id]}",
                    "amount_funded": f"{transaction.transaction.value / 10e17} {CURRENCIES[chain_id]}",
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