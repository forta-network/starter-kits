from forta_agent import Finding, FindingType, FindingSeverity

from .constants import MODEL_CREATED_TIMESTAMP

class TokenTransfersTxFinding:
    def __init__(self):
        self.model_version = MODEL_CREATED_TIMESTAMP

    def emit_finding(self):
        self.metadata['model_version'] = self.model_version

        return Finding({
            'name': self.name,
            'description': self.description,
            'alert_id': self.alert_id,
            'severity': self.severity,
            'type': self.type,
            'metadata': self.metadata,
        })

class InvalidModelFeatures(TokenTransfersTxFinding):
    def __init__(self, metadata, tx_executor):
        super().__init__()
        self.alert_id = 'INVALID-TOKEN-TRANSFERS-TX'
        self.description = f'Model input generation failed for tx executed by {tx_executor}'
        self.name = 'Invalid Model Features'
        self.severity = FindingSeverity.Low
        self.type = FindingType.Info
        self.metadata = metadata


class NormalTransaction(TokenTransfersTxFinding):
    def __init__(self, metadata, tx_executor):
        super().__init__()
        self.alert_id = 'NORMAL-TOKEN-TRANSFERS-TX'
        self.description = f'{tx_executor} executed normal tx with token transfers'
        self.name = 'Normal Transaction'
        self.severity = FindingSeverity.Info
        self.type = FindingType.Info
        self.metadata = metadata


class AnomalousTransaction(TokenTransfersTxFinding):
    def __init__(self, metadata, tx_executor):
        super().__init__()
        self.alert_id = 'ANOMALOUS-TOKEN-TRANSFERS-TX'
        self.description = f'{tx_executor} executed anomalous tx with token transfers'
        self.name = 'Anomalous Transaction'
        self.severity = FindingSeverity.Critical
        self.type = FindingType.Suspicious
        self.metadata = metadata
