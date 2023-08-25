"""Format the agent findings into Forta alerts"""

import logging

from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label

# CONSTANTS ###################################################################

BOT_ID = '0x568bf7a13b62e5041705eff995328c84ce7b037961ab6cdded927c9ab3b59e58'

# ALERTS ######################################################################

def alert_id(token) -> str:
    """Generate the alert id for a transaction of a particular token."""
    return f'BATCH-{token}-TX'

# FINDINGS ####################################################################

def FormatBatchTxFinding(
    txhash: str,
    sender: str,
    receiver: str,
    token: str,
    transfers: list,
    chain_id: int,
    confidence_score: float,
    malicious_score: float,
    alert_id: str,
    alert_rate: float
) -> Finding:
    """Structure all the metadata of the transaction in a Forta "Finding" object."""
    _labels = []

    # label the sender if the transaction is malicious
    if malicious_score >= 0.7:
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

    # raise a Forta network alert
    _finding = Finding({
        'name': f'Batch {token} transaction',
        'description': f'{sender} is transfering {token} in batch from the {receiver} contract',
        'alert_id': alert_id,
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
            'anomaly_score': str(alert_rate)},
        'labels': _labels
    })

    # keep a trace on the node
    logging.info(f'{alert_id}: found {len(transfers)} transfers of {token} bundled in {txhash}')

    return _finding
