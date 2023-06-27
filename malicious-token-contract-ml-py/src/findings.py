from forta_agent import Finding, FindingType, FindingSeverity
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad"


class TokenContractFindings:
    def __init__(
        self,
        from_address: str,
        contract_address: str,
        contained_addresses: set,
        model_score: float,
        model_threshold: float,
    ):
        self.metadata = {
            "address_contained_in_created_contract_" + str(i): address
            for i, address in enumerate(contained_addresses, 1)
        }
        self.metadata["model_score"] = str(model_score)
        self.metadata["model_threshold"] = str(model_threshold)
        self.description = f"{from_address} created contract {contract_address}"
        self.labels = []

    def malicious_contract_creation(
        self,
        chain_id: int,
        labels: list,
    ) -> Finding:
        self.metadata["anomaly_score"] = calculate_alert_rate(
            chain_id,
            BOT_ID,
            "SUSPICIOUS-TOKEN-CONTRACT-CREATION",
            ScanCountType.CONTRACT_CREATION_COUNT,
        ),
        self.label = labels
        return Finding(
            {
                "name": "Suspicious Token Contract Creation",
                "description": self.description,
                "alert_id": "SUSPICIOUS-TOKEN-CONTRACT-CREATION",
                "type": FindingType.Suspicious,
                "severity": FindingSeverity.High,
                "metadata": self.metadata,
                "labels": self.labels,
            }
        )

    def safe_contract_creation(
        self,
        chain_id: int,
        labels: list,
    ) -> Finding:
        self.label = labels
        self.metadata["anomaly_score"] = calculate_alert_rate(
            chain_id,
            BOT_ID,
            "SAFE-TOKEN-CONTRACT-CREATION",
            ScanCountType.CONTRACT_CREATION_COUNT,
        ),
        return Finding(
            {
                "name": "Safe Token Contract Creation",
                "description": self.description,
                "alert_id": "SAFE-TOKEN-CONTRACT-CREATION",
                "type": FindingType.Info,
                "severity": FindingSeverity.Info,
                "metadata": self.metadata,
                "labels": self.labels,
            }
        )

    def non_malicious_contract_creation(self, chain_id: int) -> Finding:
        self.metadata["anomaly_score"] = calculate_alert_rate(
            chain_id,
            BOT_ID,
            "NON-MALICIOUS-TOKEN-CONTRACT-CREATION",
            ScanCountType.CONTRACT_CREATION_COUNT,
        ),
        return Finding(
            {
                "name": "Non-malicious Token Contract Creation",
                "description": self.description,
                "alert_id": "NON-MALICIOUS-TOKEN-CONTRACT-CREATION",
                "type": FindingType.Info,
                "severity": FindingSeverity.Info,
                "metadata": self.metadata,
                "labels": self.labels,
            }
        )
