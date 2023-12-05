from forta_agent import create_transaction_event
import random

import agent
from web3_mock import Web3Mock, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD, EOA_ADDRESS_CONTRACT_DEPLOYER
from blockexplorer_mock import BlockExplorerMock

w3 = Web3Mock()
blockexplorer = BlockExplorerMock(1)


class TestPositiveReputation:
    def test_initialize(self):
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        agent.initialize()
        assert True, "Bot didnt successfully initialize"

    def test_detect_positive_reputation(self):
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))
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
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))
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
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))
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

    def test_detect_positive_reputation_by_age(self):
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_OLD,
                'value': 0,
                'to': "",
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'logs': [],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 1, "Bot didnt successfully detect positive reputation by age"

    def test_detect_positive_reputation_by_age_and_contract_deployment(self):
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_CONTRACT_DEPLOYER,
                'value': 0,
                'to': "",
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'logs': [],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 1, "Bot didnt successfully detect positive reputation by age"
        assert findings[0].alert_id == "POSITIVE-REPUTATION-3", "Wrong alert emitted"
