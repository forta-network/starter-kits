from forta_agent import Finding, FindingType, FindingSeverity



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
        severity: FindingSeverity,
        labels: list,
    ) -> Finding:
        self.labels = labels
        return Finding(
            {
                "name": "Early Attack Detector",
                "description": self.description,
                "alert_id": "EARLY-ATTACK-DETECTOR-1",
                "type": FindingType.Suspicious,
                "severity": severity,
                "metadata": self.metadata,
                "labels": self.labels,
            }
        )