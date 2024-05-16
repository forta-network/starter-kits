from forta_bot import Finding, FindingType, FindingSeverity
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0xf0490edadc1cd6eb2cc02e78508fbbcd6e08ea835a8fef0e399b336017fee3c8"

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
        tx_hash: str,
    ) -> Finding:
        scan_count_type = ScanCountType.CONTRACT_CREATION_COUNT
        custom_scan_count = None
        if chain_id in [43114, 10, 250, 8453]:
            scan_count_type = ScanCountType.CUSTOM_SCAN_COUNT
            custom_scan_count = 500_000

        self.metadata["anomaly_score"] = str(calculate_alert_rate(
            chain_id,
            BOT_ID,
            "SUSPICIOUS-TOKEN-CONTRACT-CREATION",
            scan_count_type,
            custom_scan_count,
        ))
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
                    "SAFE-TOKEN-CONTRACT-CREATION",
                    ScanCountType.CONTRACT_CREATION_COUNT,
                ))

        return Finding(
            {
                "name": "Safe Token Contract Creation",
                "description": self.description,
                "alert_id": "SAFE-TOKEN-CONTRACT-CREATION",
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
        if chain_id not in [43114, 10, 250, 8453]:
            self.metadata["anomaly_score"] = str(calculate_alert_rate(
                    chain_id,
                    BOT_ID,
                    "NON-MALICIOUS-TOKEN-CONTRACT-CREATION",
                    ScanCountType.CONTRACT_CREATION_COUNT,
                ))

        return Finding(
            {
                "name": "Non-malicious Token Contract Creation",
                "description": self.description,
                "alert_id": "NON-MALICIOUS-TOKEN-CONTRACT-CREATION",
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
