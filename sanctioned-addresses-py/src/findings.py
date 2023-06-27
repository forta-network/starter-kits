from forta_agent import Finding, FindingType, FindingSeverity
from bot_alert_rate import calculate_alert_rate, ScanCountType

BOT_ID = "0x9a8134e4a061e3c0098fd14f8d54c2391fb9118ff403e4b2c79faf6390f0e518"


class SanctionedAddressFinding:
    def __init__(self):
        self.data_source = 'Chainalysis'

    def emit_finding(self):
        return Finding({
            'name': self.name,
            'description': self.description,
            'alert_id': self.alert_id,
            'severity': self.severity,
            'type': self.type,
            'metadata': self.metadata,
        })


class SanctionedAddressTx(SanctionedAddressFinding):
    def __init__(self, address, chain_id):
        super().__init__()
        self.address = address
        self.alert_id = 'CHAINALYSIS-SANCTIONED-ADDR-TX'
        self.description = f'Transaction involving a sanctioned address: {self.address}'
        self.name = 'Sanctioned Address'
        self.severity = FindingSeverity.High
        self.type = FindingType.Suspicious
        self.metadata = dict(anomaly_score=calculate_alert_rate(
            chain_id,
            BOT_ID,
            self.alert_id,
            ScanCountType.TX_COUNT,
        ), sanctioned_address=self.address,
            data_source=self.data_source)


class SanctionedAddressesEvent(SanctionedAddressFinding):
    def __init__(self, addresses, chain_id):
        super().__init__()
        self.addresses = addresses
        self.alert_id = 'CHAINALYSIS-SANCTIONED-ADDR-EVENT'
        self.description = f'Addresses added to sanctions list'
        self.name = 'Sanctioned Addresses Event'
        self.severity = FindingSeverity.Medium
        self.type = FindingType.Info
        self.metadata = dict(anomaly_score=calculate_alert_rate(
            chain_id,
            BOT_ID,
            self.alert_id,
            ScanCountType.TX_COUNT,
        ), addresses=self.addresses,
            data_source=self.data_source)


class UnsanctionedAddressesEvent(SanctionedAddressFinding):
    def __init__(self, addresses, chain_id):
        super().__init__()
        self.addresses = addresses
        self.alert_id = 'CHAINALYSIS-UNSANCTIONED-ADDR-EVENT'
        self.description = f'Addresses removed from sanctions list'
        self.name = 'Unsanctioned Addresses Event'
        self.severity = FindingSeverity.Low
        self.type = FindingType.Info
        self.metadata = dict(anomaly_score=calculate_alert_rate(
            chain_id,
            BOT_ID,
            self.alert_id,
            ScanCountType.TX_COUNT,
        ), addresses=self.addresses,
            data_source=self.data_source)
