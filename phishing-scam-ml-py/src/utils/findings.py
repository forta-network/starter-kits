from bot_alert_rate import calculate_alert_rate, ScanCountType
from forta_agent import Finding, FindingType, FindingSeverity

from src.utils.constants import MODEL_CREATED_TIMESTAMP, MODEL_THRESHOLD

BOT_ID = ""


class EoaFinding:
    def __init__(self):
        self.model_version = MODEL_CREATED_TIMESTAMP
        self.model_threshold = MODEL_THRESHOLD
        self.labels = None

    def emit_finding(self):
        self.metadata["model_version"] = self.model_version
        self.metadata["model_threshold"] = self.model_threshold
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


class EoaScammer(EoaFinding):
    def __init__(self, metadata, address, labels, chain_id):
        super().__init__()
        self.alert_id = "EOA-PHISHING-SCAMMER"
        self.description = f"{address} has been identified as a phishing scammer"
        self.name = "Phishing Scammer Detected"
        self.severity = FindingSeverity.Critical
        self.type = FindingType.Suspicious
        self.metadata = metadata
        self.labels = labels
        self.metadata["anomaly_score"] = round(
            calculate_alert_rate(
                chain_id, BOT_ID, self.alert_id, ScanCountType.TX_COUNT
            ),
            6,
        )
