"""Format the agent findings into Forta alerts"""

from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label

# TEMPLATES ###################################################################

def FormatBatchTxFinding(origin: str, contract: str, token: str, transfers: list, chain_id: int, severity: int=FindingSeverity.Info) -> Finding:
    _labels = [Label({
        'entityType': EntityType.Address,
        'label': "benign",
        'entity': origin,
        'confidence': 0.80,
        'metadata': {'chain_id': chain_id}})]

    _finding = Finding({
        'name': f'Batch {token} transaction',
        'description': f'{origin} is transfering {token} in batch from the {contract} contract',
        'alert_id': f'BATCH-{token}-TX',
        'type': FindingType.Info,
        'severity': severity,
        'metadata': {
            'transfers': str(transfers),
            'count': str(len(transfers))},
        'labels': _labels
    })
    return _finding
