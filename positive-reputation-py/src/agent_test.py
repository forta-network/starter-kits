from forta_agent import create_transaction_event

import agent
from web3_mock import Web3Mock, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD
from blockexplorer_mock import BlockExplorerMock

w3 = Web3Mock()
blockexplorer = BlockExplorerMock(1)


class TestPositiveReputation:
    def test_initialize(self):
        agent.initialize()
        assert True, "Bot didnt successfully initialize"

    def test_detect_positive_reputation(self):
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_OLD,
                'value': 0,
                'to': "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
                'nonce': 500,
            },
            'block': {
                'number': 0
            },
            'logs': [],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 1, "Bot didnt successfully detect positive reputation"

    def test_detect_positive_reputation_cache(self):
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_OLD,
                'value': 0,
                'to': "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
                'nonce': 500,
            },
            'block': {
                'number': 0
            },
            'logs': [],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 1, "Bot didnt successfully detect positive reputation"

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 0, "Bot should not have emitted an alert again"

    def test_detect_positive_reputation_too_new(self):
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_NEW,
                'value': 0,
                'to': "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
                'nonce': 499,
            },
            'block': {
                'number': 0
            },
            'logs': [],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 0, "Bot incorrectly detected positive reputation"
