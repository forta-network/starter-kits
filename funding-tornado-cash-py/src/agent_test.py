from forta_agent import FindingSeverity, create_transaction_event

import agent
from constants import TORNADO_CASH_ADDRESSES, TORNADO_CASH_WITHDRAW_TOPIC
from web3_mock import EOA_ADDRESS_TC,EOA_ADDRESS_NEW, EOA_ADDRESS_OLD, Web3Mock

w3 = Web3Mock()


class TestTornadoCashFunding:

    def test_funding_new_account(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 0,
                'to': "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
            },
            'block': {
                'number': 0
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_NEW[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660"
                 }
            ],
            'receipt': {
                'logs': []}
        })
        
        findings = agent.detect_funding(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-TORNADO-CASH"
        assert findings[0].severity == FindingSeverity.Low

    def test_funding_old_account(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 0,
                'to': "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
            },
            'block': {
                'number': 0
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_OLD[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660"
                 }
            ],
            'receipt': {
                'logs': []}
        })
        
        findings = agent.detect_funding(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"
