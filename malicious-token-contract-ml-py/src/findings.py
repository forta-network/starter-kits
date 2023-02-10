from forta_agent import Finding, FindingType, FindingSeverity


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
        anomaly_score: float,
        labels: list,
    ) -> Finding:
        self.metadata["anomaly_score"] = anomaly_score
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
        anomaly_score: float,
        labels: list,
    ) -> Finding:
        self.metadata["anomaly_score"] = anomaly_score
        self.label = labels
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
