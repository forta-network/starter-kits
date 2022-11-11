from forta_agent import Finding, FindingType, FindingSeverity


class MaliciousTokenContractFindings:
    @staticmethod
    def malicious_contract_creation(
        from_address: str,
        contract_address: str,
        contained_addresses: set,
        function_sighashes: set,
        model_score: float,
        model_threshold: float,
        anomaly_score: float,
    ) -> Finding:
        metadata = {
            "address_contained_in_created_contract_" + str(i): address
            for i, address in enumerate(contained_addresses, 1)
        }
        metadata["function_sighashes"] = list(function_sighashes)
        # This contract explorer only works for Ethereum
        metadata[
            "oko_contract_explorer"
        ] = f"https://oko.palkeo.com/{contract_address}/"
        metadata["model_score"] = str(model_score)
        metadata["model_threshold"] = str(model_threshold)
        metadata["anomaly_score"] = anomaly_score

        return Finding(
            {
                "name": "Suspicious Contract Creation",
                "description": f"{from_address} created contract {contract_address}",
                "alert_id": "SUSPICIOUS-CONTRACT-CREATION",
                "type": FindingType.Suspicious,
                "severity": FindingSeverity.High,
                "metadata": metadata,
            }
        )
