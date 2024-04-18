from forta_agent import FindingSeverity, create_transaction_event
from unittest.mock import patch

import agent
from constants import TORNADO_CASH_ADDRESSES
from web3_mock import EOA_ADDRESS, Web3Mock

w3 = Web3Mock()


TORNADO_CASH_ADDRESSES = {"0xa160cdab225685da1d56aa342ad8841c3b53f291": 100, "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": 10, "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": 1, "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd": 100,
                          "0x330bdfade01ee9bf63c209ee33102dd334618e0a": 10, "0xd47438c816c9e7f2e2888e060936a499af9582b3": 1, "0xa5c2254e4253490c54cef0a4347fddb8f75a4998": 100000, "0xaf4c0b70b2ea9fb7487c7cbb37ada259579fe040": 10000, "0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339178": 1000}
RANDOM_CONTRACT = "0x1234567890123456789012345678901234567890"

class TestSuspiciousContractAgent:
    @patch("src.findings.calculate_alert_rate", return_value=0.33)
    def test_detect_money_laundering(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 0
            },
            'logs': [
                {'address': "0xa160cdab225685da1d56aa342ad8841c3b53f291",
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(
            findings) == 1, "this should have triggered a finding"
        finding = next((x for x in findings if x.alert_id ==
                       'TORNADO-CASH-DEPOSIT'), None)
        assert finding.severity == FindingSeverity.High
        assert finding.metadata == {
            "anomaly_score": 0.33, "total_funds_transferred": "100000000000000000000"}

    def test_return_no_finding_for_non_TC_contracts(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': RANDOM_CONTRACT,
            },
            'block': {
                'number': 0
            },
            'logs': [
                {'address': RANDOM_CONTRACT,
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(
            findings) == 0, "this shouldn't have triggered a finding"
        
