from forta_bot import Finding, FindingType, FindingSeverity
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0xf05b538e3f509118249e8e1b09e43bc0cd8f3d2bcd7a2a1c7f8181251fe49105"


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
        tx_hash: str,
    ) -> Finding:
        if chain_id not in [43114, 10, 250, 8453]:
            self.metadata["anomaly_score"] = str(calculate_alert_rate(
                    chain_id,
                    BOT_ID,
                    "SUSPICIOUS-CONTRACT-CREATION",
                    ScanCountType.CONTRACT_CREATION_COUNT,
                ))

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
                'source': {
                    'chains': [{'chainId': chain_id}],
                    'transactions': [{'chainId': chain_id, 'hash': tx_hash}]
                }
            }
        )

    def safe_contract_creation(
        self,
        chain_id: int,
        labels: list,
        tx_hash: str,
    ) -> Finding:
        self.label = labels
        if chain_id not in [43114, 10, 250, 8453]:
            self.metadata["anomaly_score"] = str(calculate_alert_rate(
                    chain_id,
                    BOT_ID,
                    "SAFE-CONTRACT-CREATION",
                    ScanCountType.CONTRACT_CREATION_COUNT,
                ))

        return Finding(
            {
                "name": "Safe Contract Creation",
                "description": self.description,
                "alert_id": "SAFE-CONTRACT-CREATION",
                "type": FindingType.Info,
                "severity": FindingSeverity.Info,
                "metadata": self.metadata,
                "labels": self.labels,
                'source': {
                    'chains': [{'chainId': chain_id}],
                    'transactions': [{'chainId': chain_id, 'hash': tx_hash}]
                }
            }
        )

    def non_malicious_contract_creation(self, chain_id: int, tx_hash: str) -> Finding:
        scan_count_type = ScanCountType.CONTRACT_CREATION_COUNT
        custom_scan_count = None
        if chain_id in [43114, 10, 250, 8453]:
            scan_count_type = ScanCountType.CUSTOM_SCAN_COUNT
            custom_scan_count = 500_000
        self.metadata["anomaly_score"] = str(calculate_alert_rate(
                chain_id,
                BOT_ID,
                "NON-MALICIOUS-CONTRACT-CREATION",
                scan_count_type,
                custom_scan_count,
            ))

        return Finding(
            {
                "name": "Non-malicious Contract Creation",
                "description": self.description,
                "alert_id": "NON-MALICIOUS-CONTRACT-CREATION",
                "type": FindingType.Info,
                "severity": FindingSeverity.Info,
                "metadata": self.metadata,
                "labels": self.labels,
                'source': {
                    'chains': [{'chainId': chain_id}],
                    'transactions': [{'chainId': chain_id, 'hash': tx_hash}]
                }
            }
        )
