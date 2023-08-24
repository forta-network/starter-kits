"""Format the agent findings into Forta alerts"""

import logging

from bot_alert_rate import calculate_alert_rate, ScanCountType
from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label

# CONSTANTS ###################################################################

BOT_ID = '0x568bf7a13b62e5041705eff995328c84ce7b037961ab6cdded927c9ab3b59e58'

# TEMPLATES ###################################################################

def FormatBatchTxFinding(txhash: str, sender: str, receiver: str, token: str, transfers: list, chain_id: int, confidence_score: float, malicious_score: float) -> Finding:
    _supported = chain_id not in [10, 250, 43114]
    _alert_id = f'BATCH-{token}-TX'
    _alert_rate = calculate_alert_rate(chain_id, BOT_ID, _alert_id, ScanCountType.TRANSFER_COUNT) if _supported else '0' # Optimism, Fantom & Avalanche are not supported yet
    _labels = []

    # label the sender if the transaction is malicious
    if malicious_score >= 0.6:
        _labels.append(Label({
            'entityType': EntityType.Address,
            'label': "scammer-eoa",
            'entity': sender,
            'confidence': round(malicious_score, 1),
            'metadata': {'chain_id': chain_id}}))
        _labels.append(Label({
            'entityType': EntityType.Address,
            'label': "scammer-contract",
            'entity': receiver,
            'confidence': round(malicious_score, 1),
            'metadata': {'chain_id': chain_id}}))

    _finding = Finding({
        'name': f'Batch {token} transaction',
        'description': f'{sender} is transfering {token} in batch from the {receiver} contract',
        'alert_id': _alert_id,
        'type': FindingType.Info,
        'severity': FindingSeverity.Info if malicious_score <= 0.5 else FindingSeverity.Low,
        'metadata': {
            'confidence': round(confidence_score, 1),
            'malicious': round(malicious_score, 1),
            'chain_id': str(chain_id),
            'from': sender,
            'to': receiver,
            'transfer_tokens': str(list(set([_t['token'] for _t in transfers]))),
            'transfer_count': str(len(transfers)),
            'transfer_total': str(sum([abs(int(_t['value'])) for _t in transfers])),
            'anomaly_score': str(_alert_rate)},
        'labels': _labels
    })

    logging.info(f'{_alert_id}: found {len(transfers)} transfers of {token} batched in {txhash}')

    return _finding
