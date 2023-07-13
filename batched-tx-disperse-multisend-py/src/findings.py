"""Format the agent findings into Forta alerts"""

from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label

# CONSTANTS ###################################################################

NATIVE_TOKENS = {
    1: 'ETH',
}

# TEMPLATE ####################################################################

def FormatBatchTxFinding(origin: str, contract: str, token: str, transactions: list, chain_id: int, severity: int=FindingSeverity.Info) -> Finding:
    _type = 'ERC20' if token else NATIVE_TOKENS.get(chain_id, 'ETH')

    _labels = [Label({
        'entityType': EntityType.Address,
        'label': "benign",
        'entity': origin,
        'confidence': 0.80,
        'metadata': {'chain_id': chain_id}})]

    _finding = Finding({
        'name': f'Batch {_type} transaction',
        'description': f'{origin} is transfering {_type} in batch from the {contract} contract',
        'alert_id': f'BATCHED-{_type}-TX',
        'type': FindingType.Info,
        'severity': severity,
        'metadata': {
            'transactions': str(transactions),
            'count': str(len(transactions))},
        'labels': _labels
    })
    return _finding
