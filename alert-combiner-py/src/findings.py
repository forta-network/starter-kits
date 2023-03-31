from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType
import pandas as pd
import forta_agent



class AlertCombinerFinding:

    @staticmethod
    def create_finding(block_chain_indexer, addresses: str, victim_address: str, victim_name, anomaly_score: float, severity: FindingSeverity, alert_id: str, 
        alert_event: forta_agent.alert_event.AlertEvent, alert_data: pd.DataFrame, victim_metadata: dict, anomaly_scores_by_stage: pd.DataFrame, chain_id: int) -> Finding:
        # alert_data -> 'stage', 'created_at', 'anomaly_score', 'alert_hash', 'bot_id', 'alert_id', 'addresses'

        anomaly_scores = {}
        for index, row in anomaly_scores_by_stage.iterrows():
            anomaly_scores[f'anomaly_score_stage_{row["stage"]}'] = row["anomaly_score"]
        attacker_address = {"attacker_address": addresses}
        anomaly_score = {"anomaly_score": anomaly_score}
        involved_addresses = set()
        alert_data["addresses"].apply(lambda x: [involved_addresses.add(item) for item in x])
        involved_addresses = list(involved_addresses)[0:500]
        involved_addresses = {"involved_addresses_" + str(i): address for i, address in enumerate(involved_addresses, 1)}

        alerts = alert_data[['bot_id', 'alert_id', 'alert_hash']].drop_duplicates(inplace=False)
        alerts = alerts.head(100)
        involved_alerts = {"involved_alerts_" + str(index): ','.join([row['bot_id'], row['alert_id'], row['alert_hash']]) for index, row in alerts.iterrows()}

        meta_data = {**attacker_address, **victim_metadata, **anomaly_scores, **anomaly_score, **involved_addresses, **involved_alerts}

        victim_clause = f" on {victim_name} ({victim_address.lower()})" if victim_address else ""

        labels = []
        for address in addresses.split(','):
            labels.append(Label({
                'entityType': EntityType.Address,
                'label': "attacker-eoa",
                'entity': address,
                'confidence': 0.20,
                'remove': "false",
                'metadata': {
                    'alert_id': alert_id,
                    'chain_id': chain_id
                }
            }))

            contracts = block_chain_indexer.get_contracts(address, chain_id)
            for contract in contracts:
                labels.append(Label({
                    'entityType': EntityType.Address,
                    'label': "attacker-contract",
                    'entity': contract,
                    'confidence': 0.20,
                    'remove': "false",
                    'metadata': {
                        'alert_ids': alert_id,
                        'chain_id': chain_id
                    }
    	        }))
            

        return Finding({
                       'name': 'Attack detector identified an EOA with behavior consistent with an attack',
                       'description': f'{addresses} likely involved in an attack ({alert_event.alert_hash}){victim_clause}. Anomaly score: {anomaly_score}',
                       'alert_id': alert_id,
                       'type': FindingType.Exploit,
                       'severity': severity,
                       'metadata': meta_data,
                       'labels': labels
                       })
