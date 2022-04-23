from forta_agent import create_transaction_event, FindingSeverity
import agent
from constants import TORNADO_CASH_ADDRESSES
from web3_mock import Web3Mock, EOA_ADDRESS


w3 = Web3Mock()


class TestSuspiciousContractAgent:

    def test_detect_money_laundering_at_threshold_within_blockrange(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'transaction_position': 0,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
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
            },
            'block': {
                'number': 1
            },
            'traces': [
                {'type': 'call',
                 'transaction_position': 0,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
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
            },
            'block': {
                'number': 2
            },
            'traces': [
                {'type': 'call',
                 'transaction_position': 0,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"

    def test_detect_money_laundering_at_threshold_outside_blockrange(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'transaction_position': 0,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
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
            },
            'block': {
                'number': 1
            },
            'traces': [
                {'type': 'call',
                 'transaction_position': 0,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
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
            },
            'block': {
                'number': 101
            },
            'traces': [
                {'type': 'call',
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding as third transaction happened outside block range"

    def test_detect_money_laundering_below_threshold(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'transaction_position': 0,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
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
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'transaction_position': 0,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[137],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 },
                {'type': 'call',
                 'transaction_position': 1,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[137],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 },
                {'type': 'call',
                 'transaction_position': 2,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[137],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding"

    def test_detect_money_laundering_at_threshold_mainnet(self):
        agent.initialize()

        w3.chain_id = 1

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'transaction_position': 0,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 },
                {'type': 'call',
                 'transaction_position': 1,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 },
                {'type': 'call',
                 'transaction_position': 2,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[1],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        finding = next((x for x in findings if x.alert_id == 'POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH'), None)
        assert finding.severity == FindingSeverity.High
        assert finding.metadata == {"total_funds_transferred": "3"}

    def test_detect_money_laundering_below_threshold_polygon(self):
        agent.initialize()

        w3.eth.chain_id = 137

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'transaction_position': 0,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[137],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 },
                {'type': 'call',
                 'transaction_position': 1,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[137],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
                 },
                {'type': 'call',
                 'transaction_position': 2,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[137],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }
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

        traces = []
        for i in range(100):
            traces.append({'type': 'call',
                 'transaction_position': i,
                 'action': {
                     'to': TORNADO_CASH_ADDRESSES[137],
                     'from': '0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b',
                     'value': 1,
                 }})

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
            },
            'block': {
                'number': 0
            },
            'traces': traces,
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_money_laundering(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
