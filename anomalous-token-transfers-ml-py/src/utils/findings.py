from bot_alert_rate import calculate_alert_rate, ScanCountType
from forta_agent import Finding, FindingType, FindingSeverity

from src.utils.constants import MODEL_CREATED_TIMESTAMP, ANOMALY_THRESHOLD
BOT_ID = "0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8"


class TokenTransfersTxFinding:
    def __init__(self):
        self.model_version = MODEL_CREATED_TIMESTAMP
        self.anomaly_threshold = ANOMALY_THRESHOLD
        self.labels = None

    def emit_finding(self):
        self.metadata["model_version"] = self.model_version
        self.metadata["model_threshold"] = self.anomaly_threshold
        finding = {
            "name": self.name,
            "description": self.description,
            "alert_id": self.alert_id,
            "severity": self.severity,
            "type": self.type,
            "metadata": self.metadata,
        }
        if self.labels is not None:
            finding["labels"] = self.labels

        return Finding(finding)


class InvalidModelFeatures(TokenTransfersTxFinding):
    def __init__(self, metadata, tx_executor):
        super().__init__()
        self.alert_id = "INVALID-TOKEN-TRANSFERS-TX"
        self.description = (
            f"Model input generation failed for tx executed by {tx_executor}"
        )
        self.name = "Invalid Model Features"
        self.severity = FindingSeverity.Low
        self.type = FindingType.Info
        self.metadata = metadata


class NormalTransaction(TokenTransfersTxFinding):
    def __init__(self, metadata, tx_executor):
        super().__init__()
        self.alert_id = "NORMAL-TOKEN-TRANSFERS-TX"
        self.description = f"{tx_executor} executed normal tx with token transfers"
        self.name = "Normal Transaction"
        self.severity = FindingSeverity.Info
        self.type = FindingType.Info
        self.metadata = metadata


class AnomalousTransaction(TokenTransfersTxFinding):
    def __init__(self, metadata, tx_executor, labels, chain_id):
        super().__init__()
        self.alert_id = "ANOMALOUS-TOKEN-TRANSFERS-TX"
        self.description = f"{tx_executor} executed anomalous tx with token transfers"
        self.name = "Anomalous Transaction"
        self.severity = FindingSeverity.Critical
        self.type = FindingType.Suspicious
        self.metadata = metadata
        self.labels = labels
        self.metadata["anomaly_score"] = round(
            calculate_alert_rate(
                chain_id, BOT_ID, self.alert_id, ScanCountType.TRANSFER_COUNT
            ),
            6,
        )
