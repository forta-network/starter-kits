from forta_agent import Finding, FindingSeverity, FindingType


class TimeSeriesAnalyzerFinding:

    @staticmethod
    def breakout(direction: str, expected_value: float, range_boundary: float, observed_value: float, contract_address: str, bot_id: str, alert_name: str, type: FindingType, severity: FindingSeverity) -> Finding:

        meta_data = {"Expected_value": str(expected_value), "Range_boundary": str(range_boundary), "Observed_value": str(observed_value), "Contract_address": contract_address}

        return Finding({
            'name': 'Time series analysis bot identified breakout',
            'description': f'{direction} breakout on bot {bot_id}, alert {alert_name}',
            'alert_id': f'{direction.upper()}-BREAKOUT',
            'type': type,
            'severity': severity,
            'metadata': meta_data
        })
