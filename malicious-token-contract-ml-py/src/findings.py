from forta_agent import Finding, FindingType, FindingSeverity


class MaliciousTokenContractFindings:
    @staticmethod
    def malicious_contract_creation(
        from_address: str,
        token_type: str,
        contract_address: str,
        contained_addresses: set,
        model_score: float,
        model_threshold: float,
        anomaly_score: float,
        labels: list
    ) -> Finding:
        metadata = {
            "address_contained_in_created_contract_" + str(i): address
            for i, address in enumerate(contained_addresses, 1)
        }
        metadata["model_score"] = str(model_score)
        metadata["model_threshold"] = str(model_threshold)
        metadata["anomaly_score"] = anomaly_score

        return Finding(
            {
                "name": "Suspicious Token Contract Creation",
                "description": f"{from_address} created {token_type}-like contract {contract_address}",
                "alert_id": "SUSPICIOUS-TOKEN-CONTRACT-CREATION",
                "type": FindingType.Suspicious,
                "severity": FindingSeverity.High,
                "metadata": metadata,
                "labels": labels
            }
        )
