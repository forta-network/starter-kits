from forta_agent import Finding, FindingSeverity, FindingType, EntityType

    
class AddressPoisoningFinding:

    def create_finding(transaction_event, anomaly_score, log_length, attackers, victims, alert_type):

        alert_description = {
            "ADDRESS-POISONING-ZERO-VALUE": "zero value",
            "ADDRESS-POISONING-LOW-VALUE": "low value",
            "ADDRESS-POISONING-FAKE-TOKEN": "fake token"
        }

        finding = Finding(
                    {
                        "name": "Possible Address Poisoning",
                        "description": f"Possible {alert_description[alert_type]} address poisoning transaction triggered by eoa - {transaction_event.from_} calling contract - {transaction_event.to}",
                        "alert_id": alert_type,
                        "type": FindingType.Suspicious,
                        "severity": FindingSeverity.Medium,
                        "metadata": {
                            "phishing_eoa": transaction_event.from_,
                            "phishing_contract": transaction_event.to,
                            "logs_length": log_length,
                            "attacker_addresses": attackers,
                            "victim_addresses": victims,
                            "anomaly_score": anomaly_score
                        },
                        "labels": [
                            {
                                "entityType": EntityType.Address,
                                "entity": transaction_event.from_,
                                "label": "attacker-eoa",
                                "confidence": 0.7
                            },
                            {
                                "entityType": EntityType.Address,
                                "entity": transaction_event.to,
                                "label": "attacker-contract",
                                "confidence": 0.7
                            },
                            {
                                "entityType": EntityType.Transaction,
                                "entity": transaction_event.hash,
                                "label": "address-poisoning",
                                "confidence": 0.7
                            },
                        ]
                    }  
                )

        return finding