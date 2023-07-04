from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label

def FormatBatchTxFinding(origin: str, contract: str, transactions: list, chain_id: int) -> Finding:
    _labels = [Label({
        'entityType': EntityType.Address,
        'label': "benign",
        'entity': origin,
        'confidence': 0.80,
        'metadata': {'chain_id': chain_id}})]

    _finding = Finding({
        'name': f'Batch ERC20 transaction',
        'description': f'{origin} is transfering ERC20s in batch from the {contract} contract',
        'alert_id': 'BATCHED-ERC20-TX',
        'type': FindingType.Info,
        'severity': FindingSeverity.Info,
        'metadata': {
            'transactions': str(transactions),
            'count': str(len(transactions))},
        'labels': _labels
    })
    return _finding
