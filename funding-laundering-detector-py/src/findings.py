from forta_agent import Finding, FindingType, FindingSeverity
from src.utils import get_severity, get_severity_laundering, calculate_anomaly_score

F_INFO_COUNT = 0
F_LOW_COUNT = 0
F_MEDIUM_COUNT = 0
F_HIGH_COUNT = 0
F_CRITICAL_COUNT = 0
F_NC_HIGH_COUNT = 0
F_NC_CRITICAL_COUNT = 0
L_INFO_COUNT = 0
L_LOW_COUNT = 0
L_MEDIUM_COUNT = 0
L_HIGH_COUNT = 0
L_CRITICAL_COUNT = 0


class FundingLaunderingFindings:

    @staticmethod
    def funding(from_, to, usd, token, type_, tx_hash, labels, total_transactions, chain_id):
        global F_LOW_COUNT
        global F_MEDIUM_COUNT
        global F_HIGH_COUNT
        global F_CRITICAL_COUNT
        global F_INFO_COUNT

        severity = get_severity(usd, chain_id)
        current_count = 0

        if severity == FindingSeverity.Critical:
            F_CRITICAL_COUNT += 1
            current_count = F_CRITICAL_COUNT
        elif severity == FindingSeverity.High:
            F_HIGH_COUNT += 1
            current_count = F_HIGH_COUNT
        elif severity == FindingSeverity.Medium:
            F_MEDIUM_COUNT += 1
            current_count = F_MEDIUM_COUNT
        elif severity == FindingSeverity.Low:
            F_LOW_COUNT += 1
            current_count = F_LOW_COUNT
        elif severity == FindingSeverity.Info:
            F_INFO_COUNT += 1
            current_count = F_INFO_COUNT

        return Finding({
            'name': f'Funding Alert',
            'description': f'{to} was funded using {type_ if not type_ == "unknown" else ""} {from_}',
            'alert_id': 'FLD_FUNDING',
            'severity': severity,
            'type': FindingType.Suspicious if severity != FindingSeverity.Info else FindingType.Info,
            'metadata': {
                'funded_address': to,
                'source_address': from_,
                'anomaly_score': calculate_anomaly_score(current_count, total_transactions),
                'source_type': type_,
                'usd_volume': usd,
                'token': token,
                'tx_hash': tx_hash,
            },
            'labels': labels
        })

    @staticmethod
    def laundering(from_, to, usd, token, is_new, type_, tx_hash, labels, total_transactions, chain_id):
        global L_LOW_COUNT
        global L_MEDIUM_COUNT
        global L_HIGH_COUNT
        global L_CRITICAL_COUNT
        global L_INFO_COUNT

        severity = get_severity_laundering(usd, chain_id)
        current_count = 0

        if severity == FindingSeverity.Critical:
            L_CRITICAL_COUNT += 1
            current_count = L_CRITICAL_COUNT
        elif severity == FindingSeverity.High:
            L_HIGH_COUNT += 1
            current_count = L_HIGH_COUNT
        elif severity == FindingSeverity.Medium:
            L_MEDIUM_COUNT += 1
            current_count = L_MEDIUM_COUNT
        elif severity == FindingSeverity.Low:
            L_LOW_COUNT += 1
            current_count = L_LOW_COUNT
        elif severity == FindingSeverity.Info:
            L_INFO_COUNT += 1
            current_count = L_INFO_COUNT

        return Finding({
            'name': f'Laundering Alert',
            'description': f'{from_} is engaged in money laundering behavior using {type_ if not type_ == "unknown" else ""} {to}',
            'alert_id': 'FLD_Laundering',
            'type': FindingType.Suspicious if get_severity_laundering(
                usd, chain_id) != FindingSeverity.Info else FindingType.Info,
            'severity': severity,
            'metadata': {
                'laundering_address': from_,
                'newly_created': is_new,
                'anomaly_score': calculate_anomaly_score(current_count, total_transactions),
                'target_address': to,
                'target_type': type_,
                'usd_volume': usd,
                'token': token,
                'tx_hash': tx_hash,
            },
            'labels': labels
        })

    @staticmethod
    def funding_newly_created(from_, to, usd, token, type_, tx_hash, labels, total_transactions):
        global F_NC_HIGH_COUNT
        global F_NC_CRITICAL_COUNT

        severity = FindingSeverity.Critical if type_ != 'exchange' and type_ != 'dex' else FindingSeverity.High
        current_count = 0

        if severity == FindingSeverity.Critical:
            F_NC_CRITICAL_COUNT += 1
            current_count = F_NC_CRITICAL_COUNT
        elif severity == FindingSeverity.High:
            F_NC_HIGH_COUNT += 1
            current_count = F_NC_HIGH_COUNT

        return Finding({
            'name': f'Newly Created Account Funding Alert',
            'description': f'new {to} was funded using {type_ if not type_ == "unknown" else ""} {from_}',
            'alert_id': 'FLD_NEW_FUNDING',
            'severity': severity,
            'type': FindingType.Suspicious,
            'metadata': {
                'funded_address': to,
                'source_address': from_,
                'anomaly_score': calculate_anomaly_score(current_count, total_transactions),
                'source_type': type_,
                'usd_volume': usd,
                'token': token,
                'tx_hash': tx_hash,
            },
            'labels': labels
        })
