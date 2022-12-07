from forta_agent import Finding, FindingType, FindingSeverity, Label, EntityType, LabelType


class VictimNotificationFinding:

    @staticmethod
    def Victim(victim_address: str, notifier_address: str) -> Finding:
        # labels = [Label({
    	# 	    'entity_type': EntityType.Address,
    	# 	    'label_type': LabelType.Victim,
    	# 	    'entity': victim_address,
        #         'confidence': 0.99,
        #         'custom_value': ""
    	#     })]

        finding = Finding({
            'name': 'Victim Notified',
            'description': f'{victim_address} was notified to be a victim by {notifier_address}',
            'alert_id': 'VICTIM-NOTIFICATION-1',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
        #    'labels': labels
        })
        return finding
