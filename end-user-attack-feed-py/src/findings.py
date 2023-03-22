# Copyright 2022 The Forta Foundation

from forta_agent import Finding, FindingType, FindingSeverity, EntityType, AlertEvent


class NegativeReputationFinding:

    @staticmethod
    def create_finding(attacker_addresses: set, alert_event: AlertEvent, source: str) -> Finding:
        labels = []
        for attacker_address in attacker_addresses:
            labels.append({"entity": attacker_address,
                    "entityType": EntityType.Address,
                    "label": "attacker",
                    "confidence": 0.6})

        return Finding({
                       'name': 'Negative Reputation (end-user attack) Assigned',
                       'description': f'{source} Alert: EOA {attacker_address} was assigned negative reputation (end-user attack)',
                       'alert_id': 'NEGATIVE-REPUTATION-END-USER-ATTACK-1',
                       'type': FindingType.Exploit,
                       'severity': FindingSeverity.Critical,
                       'metadata': {"bot_id": alert_event.bot_id, "alert_id": alert_event.alert_id, "alert_hash": alert_event.alert_hash},
                       'labels': labels
                       })
