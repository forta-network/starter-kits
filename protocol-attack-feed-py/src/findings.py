# Copyright 2022 The Forta Foundation

from forta_agent import Finding, FindingType, FindingSeverity, EntityType, AlertEvent


class NegativeReputationFinding:

    @staticmethod
    def create_finding(attacker_address: str, victim_address: str, victim_name: str, alert_event: AlertEvent) -> Finding:
        labels = [{"entity": attacker_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.6}]

        victim_clause = ""
        if victim_address is not None and victim_address != "":
            labels = [{"entity": attacker_address,
                       "entity_type": EntityType.Address,
                       "label": "victim",
                       "confidence": 0.4}]

            labels = [{"entity": attacker_address,
                       "entity_type": EntityType.Unknown,
                       "label": victim_name,
                       "confidence": 1.0}]

            victim_clause = f" on victim {victim_address} {victim_name}"

        return Finding({
                       'name': 'Negative Reputation (protocol attack) Assigned',
                       'description': f'EOA {attacker_address} was assigned negative reputation (protocol attack) {victim_clause}',
                       'alert_id': 'NEGATIVE-REPUTATION-PROTOCOL-ATTACK-1',
                       'type': FindingType.Exploit,
                       'severity': FindingSeverity.Critical,
                       'metadata': {"bot_id": alert_event.bot_id, "alert_id": alert_event.alert_id, "alert_hash": alert_event.alert_hash},
                       'labels': labels
                       })
