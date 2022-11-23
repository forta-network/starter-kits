from forta_agent import Finding, FindingType, FindingSeverity
import pandas as pd
import forta_agent


class AlertCombinerFinding:

    @staticmethod
    def create_finding(address: str, anomaly_score: float, alert_event: forta_agent.alert_event.AlertEvent, alert_data: pd.DataFrame) -> Finding:
        # alert_data -> 'stage', 'created_at', 'anomaly_score', 'alert_hash', 'bot_id', 'alert_id', 'addresses'

        attacker_address = {"attacker_address": address}
        anomaly_score = {"anomaly_score": anomaly_score}
        involved_addresses = set()
        alert_data["addresses"].apply(lambda x: [involved_addresses.add(item) for item in x])
        involved_addresses = list(involved_addresses)[0:500]
        involved_addresses = {"involved_addresses_" + str(i): address for i, address in enumerate(involved_addresses, 1)}

        alerts = alert_data[['bot_id', 'alert_id', 'alert_hash']].drop_duplicates(inplace=False)
        alerts = alerts.head(100)
        involved_alerts = {"involved_alerts_" + str(index): ','.join([row['bot_id'], row['alert_id'], row['alert_hash']]) for index, row in alerts.iterrows()}

        meta_data = {**attacker_address, **anomaly_score, **involved_addresses, **involved_alerts}

        return Finding({
            'name': 'Attack detector identified an EOA with behavior consistent with an attack',
            'description': f'{address} likely involved in an attack ({alert_event.alert_hash}). Anomaly score: {anomaly_score}',
            'alert_id': alert_event.alert_hash,
            'type': FindingType.Exploit,
            'severity': FindingSeverity.Critical,
            'metadata': meta_data
        })
