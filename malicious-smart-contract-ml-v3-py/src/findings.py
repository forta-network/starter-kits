from forta_agent import Finding, FindingType, FindingSeverity


class MaliciousTokenContractFindings:
    @staticmethod
    def malicious_contract_creation(
        from_address: str,
        contract_address: str,
        contained_addresses: set,
        model_score: float,
        model_threshold: float,
        anomaly_score: float,
        labels: list,
        error: str = None,
    ) -> Finding:
        metadata = {
            "address_contained_in_created_contract_" + str(i): address
            for i, address in enumerate(contained_addresses, 1)
        }
        # This contract explorer only works for Ethereum
        metadata[
            "oko_contract_explorer"
        ] = f"https://oko.palkeo.com/{contract_address}/"
        metadata["model_score"] = str(model_score)
        metadata["model_threshold"] = str(model_threshold)
        metadata["anomaly_score"] = anomaly_score
        description = (
            f"{from_address} created contract {contract_address}"
            if error is None
            else f"{from_address} failed to create contract {contract_address} with err: {error}"
        )

        return Finding(
            {
                "name": "Suspicious Contract Creation",
                "description": description,
                "alert_id": "SUSPICIOUS-CONTRACT-CREATION",
                "type": FindingType.Suspicious,
                "severity": FindingSeverity.High,
                "metadata": metadata,
                "labels": labels,
            }
        )
