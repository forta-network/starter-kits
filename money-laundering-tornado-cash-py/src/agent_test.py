from forta_agent import FindingSeverity, create_transaction_event, EntityType

import agent
from constants import TORNADO_CASH_ADDRESSES
from web3_mock import EOA_ADDRESS, Web3Mock

w3 = Web3Mock()


class TestSuspiciousContractAgent:

    def test_detect_money_laundering_at_threshold_within_blockrange(self):
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
                {'address': TORNADO_CASH_ADDRESSES[1],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 1
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 2
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        finding = next((x for x in findings if x.alert_id == 'POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH'), None)
        assert finding.severity == FindingSeverity.High
        assert finding.metadata == {"anomaly_score": 0.3333333333333333, "total_funds_transferred": "300"}

        assert finding.metadata["anomaly_score"] == 0.3333333333333333, "should have anomaly score of 1/3"
        assert finding.labels[0].toDict()["entity"] == EOA_ADDRESS, "should have EOA address as label"
        assert finding.labels[0].toDict()["entity_type"] == EntityType.Address, "should have label_type address"
        assert finding.labels[0].toDict()["label"] == 'attacker', "should have attacker as label"
        assert finding.labels[0].toDict()["confidence"] == 0.5, "should have 0.3 as label confidence"


    def test_detect_money_laundering_at_threshold_outside_blockrange(self):
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
                {'address': TORNADO_CASH_ADDRESSES[1],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 1
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 241
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding as third transaction happened outside block range"

    def test_detect_money_laundering_below_threshold(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 2
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"

    def test_detect_money_laundering_incorrect_tornado_cash_contract_mainnet(self):
        agent.initialize()

        w3.chain_id = 1

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
                {'address': TORNADO_CASH_ADDRESSES[137],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding"

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 1
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[137],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding"

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 2
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[137],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding"

    def test_detect_money_laundering_below_threshold_polygon(self):
        agent.initialize()

        w3.eth.chain_id = 137

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
                {'address': TORNADO_CASH_ADDRESSES[137],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding"

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 1
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[137],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding"

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 100000000000000000000,
                'to': TORNADO_CASH_ADDRESSES,
            },
            'block': {
                'number': 2
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[137],
                 'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding"

    def test_detect_money_laundering_at_threshold_polygon(self):
        agent.initialize()

        w3.eth.chain_id = 137

        for i in range(100):
            tx_event = create_transaction_event({
                'transaction': {
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'value': 100000000000000000000,
                    'to': TORNADO_CASH_ADDRESSES,
                },
                'block': {
                    'number': i
                },
                'logs': [
                    {'address': TORNADO_CASH_ADDRESSES[137],
                     'topics': ['0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'],
                     }
                ],
                'receipt': {
                    'logs': []}
            })
            findings = agent.detect_money_laundering(w3, tx_event)

        assert len(findings) == 1, "this should have triggered a finding"
