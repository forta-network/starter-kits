"""Format the agent findings into Forta alerts"""

from bot_alert_rate import calculate_alert_rate, ScanCountType
from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label

# CONSTANTS ###################################################################

BOT_ID = '0x518619e99547b3c400f76d80c5371081f6952840d7c18b755082e7ddca5f644c'

# TEMPLATES ###################################################################

def FormatBatchTxFinding(sender: str, receiver: str, token: str, transfers: list, chain_id: int, confidence_score: float, malicious_score: float) -> Finding:
    _alert_id = f'BATCH-{token}-TX'
    _alert_rate = '0' #calculate_alert_rate(chain_id, BOT_ID, _id, ScanCountType.TRANSFER_COUNT)
    _labels = []

    # label the sender if the transaction is malicious
    if malicious_score >= 0.6:
        _labels.append(Label({
            'entityType': EntityType.Address,
            'label': "benign",
            'entity': sender,
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
            'chain_id': str(chain_id),
            'from': sender,
            'to': receiver,
            'token': token,
            'transfers': str(transfers),
            'count': str(len(transfers)),
            'anomaly_score': _alert_rate},
        'labels': _labels
    })

    return _finding
