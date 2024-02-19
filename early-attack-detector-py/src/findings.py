from forta_agent import Finding, FindingType, FindingSeverity
from bot_alert_rate import calculate_alert_rate, ScanCountType

from src.constants import BOT_ID


class ContractFindings:
    def __init__(
        self,
        from_address: str,
        contract_address: str,
        contained_addresses: set,
        function_signatures: set,
        model_score: float,
        model_threshold: float,
        error: str = None,
    ):
        self.metadata = {
            "address_contained_in_created_contract_" + str(i): address
            for i, address in enumerate(contained_addresses, 1)
        }
        self.metadata["function_signatures"] = ",".join(function_signatures)
        # This contract explorer only works for Ethereum
        self.metadata[
            "oko_contract_explorer"
        ] = f"https://oko.palkeo.com/{contract_address}/"
        self.metadata["model_score"] = str(model_score)
        self.metadata["model_threshold"] = str(model_threshold)
        self.description = (
            f"{from_address} created contract {contract_address}"
            if error is None
            else f"{from_address} failed to create contract {contract_address} with err: {error}"
        )
        self.labels = []

    def malicious_contract_creation(
        self,
        chain_id: int,
        labels: list,
    ) -> Finding:
        if chain_id not in [43114, 10, 250]:
            self.metadata["anomaly_score"] = (
                calculate_alert_rate(
                    chain_id,
                    BOT_ID,
                    "SUSPICIOUS-CONTRACT-CREATION",
                    ScanCountType.CONTRACT_CREATION_COUNT,
                ),
            )
        self.label = labels
        return Finding(
            {
                "name": "Suspicious Contract Creation",
                "description": self.description,
                "alert_id": "SUSPICIOUS-CONTRACT-CREATION",
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
        if chain_id not in [43114, 10, 250]:
            self.metadata["anomaly_score"] = (
                calculate_alert_rate(
                    chain_id,
                    BOT_ID,
                    "SAFE-CONTRACT-CREATION",
                    ScanCountType.CONTRACT_CREATION_COUNT,
                ),
            )
        return Finding(
            {
                "name": "Safe Contract Creation",
                "description": self.description,
                "alert_id": "SAFE-CONTRACT-CREATION",
                "type": FindingType.Info,
                "severity": FindingSeverity.Info,
                "metadata": self.metadata,
                "labels": self.labels,
            }
        )

    def non_malicious_contract_creation(self, chain_id: int) -> Finding:
        scan_count_type = ScanCountType.CONTRACT_CREATION_COUNT
        custom_scan_count = None
        if chain_id in [43114, 10, 250]:
            scan_count_type = ScanCountType.CUSTOM_SCAN_COUNT
            custom_scan_count = 500_000
        self.metadata["anomaly_score"] = (
            calculate_alert_rate(
                chain_id,
                BOT_ID,
                "NON-MALICIOUS-CONTRACT-CREATION",
                scan_count_type,
                custom_scan_count,
            ),
        )
        return Finding(
            {
                "name": "Non-malicious Contract Creation",
                "description": self.description,
                "alert_id": "NON-MALICIOUS-CONTRACT-CREATION",
                "type": FindingType.Info,
                "severity": FindingSeverity.Info,
                "metadata": self.metadata,
                "labels": self.labels,
            }
        )