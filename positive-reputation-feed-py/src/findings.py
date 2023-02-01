# Copyright 2022 The Forta Foundation

from forta_agent import Finding, FindingType, FindingSeverity, EntityType


class PositiveReputationFinding:

    @staticmethod
    def create_finding(address: str, base_bots: list) -> Finding:
        base_bots_metadata = {"base_bots_" + str(i): address for i, address in enumerate(base_bots, 1)}

        confidence = 0.5 if len(base_bots) > 1 else 0.3

        labels = [{"entity": address,
                   "entity_type": EntityType.Address,
                   "label": "attacker",
                   "confidence": confidence}]  # very low

        return Finding({
                       'name': 'Positive Reputation Assigned',
                       'description': f'EOA {address} was assigned positive reputation.',
                       'alert_id': 'POSITIVE-REPUTATION-1',
                       'type': FindingType.Info,
                       'severity': FindingSeverity.Info,
                       'metadata': base_bots_metadata,
                       'labels': labels
                       })
