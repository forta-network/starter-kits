from forta_agent import Finding, FindingType, FindingSeverity, EntityType
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2"


class MoneyLaunderingTornadoCashFindings:

    @staticmethod
    def possible_money_laundering_tornado_cash(from_address: str, funds_transferred: int, chain_id: int) -> Finding:
        labels = [{"entity": from_address,
                   "entity_type": EntityType.Address,
                   "label": "attacker",
                   "confidence": 0.7}]

        metadata = {"total_funds_transferred": str(funds_transferred)}

        if chain_id not in [43114, 10, 250]:
            metadata['anomaly_score'] = calculate_alert_rate(
                chain_id,
                BOT_ID,
                'TORNADO-CASH-DEPOSIT',
                ScanCountType.TRANSFER_COUNT,
            )

        return Finding({
            'name': 'Possible Money Laundering With Tornado Cash',
            'description': f'{from_address} potentially engaged in money laundering',
            'alert_id': 'TORNADO-CASH-DEPOSIT',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'metadata': metadata,
            "labels": labels
        })
