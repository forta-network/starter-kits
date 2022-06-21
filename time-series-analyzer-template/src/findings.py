import pandas as pd
from forta_agent import Finding, FindingSeverity, FindingType


class TimeSeriesAnalyzerFinding:

    @staticmethod
    def breakout(direction: str, expected_value: float, range_boundary: float, observed_value: float, contract_address: str, timeseries_data: pd, bot_id: str, alert_id: str, type: FindingType, severity: FindingSeverity) -> Finding:
        timeseries_data_values = {"ts_value" + str(i): ts_value for i, ts_value in enumerate(timeseries_data, 1)}

        meta_data = {"Expected_value": expected_value, "Range_boundary": range_boundary, "Observed_value": observed_value, "Contract_address": contract_address, **timeseries_data_values}

        return Finding({
            'name': 'Time series analysis bot identified upside breakout',
            'description': f'{direction} breakout on bot {bot_id}, alert {alert_id}',
            'alert_id': f'{direction.upper()}-BREAKOUT',
            'type': type,
            'severity': severity,
            'metadata': meta_data
        })
