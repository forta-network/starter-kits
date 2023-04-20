import time
from datetime import datetime

from forta_agent import FindingSeverity, FindingType, create_transaction_event, EntityType
import agent
from blockexplorer_mock import BlockExplorerMock
from web3_mock import (CONTRACT_NO_ADDRESS, CONTRACT_WITH_ADDRESS, EOA_ADDRESS,
                       Web3Mock)
from unittest.mock import patch

w3 = Web3Mock()
blockexplorer = BlockExplorerMock(1)


class TestUnverifiedContractAgent:
    def test_get_opcode_addresses_eoa(self):
        addresses = agent.get_opcode_addresses(w3, EOA_ADDRESS)
        assert len(addresses) == 0, "should be empty"

    def test_get_opcode_addresses_no_addr(self):
        addresses = agent.get_opcode_addresses(w3, CONTRACT_NO_ADDRESS)
        assert len(addresses) == 0, "should not be empty"

    def test_get_opcode_addresses_with_addr(self):
        addresses = agent.get_opcode_addresses(w3, CONTRACT_WITH_ADDRESS)
        assert len(addresses) == 1, "should not be empty"

    def test_storage_addresses_with_addr(self):
        addresses = agent.get_opcode_addresses(w3, CONTRACT_WITH_ADDRESS)
        assert len(addresses) == 1, "should not be empty"

    def test_storage_addresses_on_eoa(self):
        addresses = agent.get_opcode_addresses(w3, EOA_ADDRESS)
        assert len(addresses) == 0, "should be empty; EOA has no storage"

    def test_calc_contract_address(self):
        contract_address = agent.calc_contract_address(w3, EOA_ADDRESS, 9)
        assert contract_address == "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7", "should be the same contract address"

    @patch("src.findings.calculate_alert_rate", return_value=1.0)
    def test_detect_unverified_contract_with_unverified_contract_no_trace(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            {
                "transaction": {
                    "hash": "0",
                    "from": EOA_ADDRESS,
                    "nonce": 9,
                },
                'block': {
                    'number': 0,
                    'timestamp': datetime.now().timestamp(),
                },
                "receipt": {"logs": []},
            }
        )
        agent.cache_contract_creation(w3, blockexplorer, tx_event)
        time.sleep(1 * 60 + 10)
        agent.detect_unverified_contract_creation(
            w3, blockexplorer, wait_time=1, infinite=False)
        assert len(agent.FINDINGS_CACHE) == 1, "should have 1 finding"
        assert agent.FINDINGS_CACHE[0].metadata["anomaly_score"] == 1.0, "should have anomaly score of 1.0"
        assert agent.FINDINGS_CACHE[0].labels[0].toDict(
        )["entity"] == EOA_ADDRESS, "should have EOA address as label"
        assert agent.FINDINGS_CACHE[0].labels[0].toDict(
        )["entity_type"] == EntityType.Address, "should have label_type address"
        assert agent.FINDINGS_CACHE[0].labels[0].toDict(
        )["label"] == 'attacker', "should have attacker as label"
        assert agent.FINDINGS_CACHE[0].labels[0].toDict(
        )["confidence"] == 0.3, "should have 0.3 as label confidence"
        assert agent.FINDINGS_CACHE[0].labels[1].toDict(
        )["entity"] == '0x728ad672409DA288cA5B9AA85D1A55b803bA97D7', "should have contract address as label"
        assert agent.FINDINGS_CACHE[0].labels[1].toDict(
        )["label"] == 'attacker_contract', "should have attacker as label"
        assert agent.FINDINGS_CACHE[0].labels[1].toDict(
        )["confidence"] == 0.3, "should have 0.3 as label confidence"
        assert agent.FINDINGS_CACHE[0].labels[1].toDict(
        )["entity_type"] == EntityType.Address, "should have label_type address"

    def test_detect_unverified_contract_with_unverified_contract_trace(self):
        agent.initialize()

        tx_event = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'to': '0x0000000000000000000000000000000000000000',
                'nonce': 9,

            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'traces': [{'type': 'create',
                        'action': {
                            'from': EOA_ADDRESS,
                            'value': 1,
                        }
                        }
                       ],
            'receipt': {
                'logs': []}
        })

        agent.cache_contract_creation(w3, blockexplorer, tx_event)
        time.sleep(1 * 60 + 10)
        agent.detect_unverified_contract_creation(
            w3, blockexplorer, wait_time=1, infinite=False)
        assert len(agent.FINDINGS_CACHE) == 1, "should have 1 finding"
        finding = next((x for x in agent.FINDINGS_CACHE if x.alert_id ==
                       'UNVERIFIED-CODE-CONTRACT-CREATION'), None)
        assert finding.severity == FindingSeverity.Medium
        assert finding.type == FindingType.Suspicious
        assert finding.description == f'{EOA_ADDRESS} created contract 0x728ad672409DA288cA5B9AA85D1A55b803bA97D7'
        assert len(finding.metadata) > 0

    def test_detect_unverified_contract_with_verified_contract(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,  # verified contract
            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'traces': [{'type': 'create',
                        'action': {
                            'from': EOA_ADDRESS,
                            'value': 1,
                        }
                        }
                       ],
            'receipt': {
                'logs': []}
        })

        agent.cache_contract_creation(w3, blockexplorer, tx_event)
        time.sleep(1 * 60 + 10)
        agent.detect_unverified_contract_creation(
            w3, blockexplorer, wait_time=1, infinite=False)

        assert len(agent.FINDINGS_CACHE) == 0, "should have 0 finding"

    def test_detect_unverified_contract_call_only(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 7,
                'to': '0x0000000000000000000000000000000000000000'
            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'traces': [{'type': 'call',
                        'action': {
                            'from': EOA_ADDRESS,
                            'to': '0x728ad672409DA288cA5B9AA85D1A55b803bA97D7',  # unverified contract
                            'value': 1,
                        }
                        }
                       ],
            'receipt': {
                'logs': []}
        })

        agent.cache_contract_creation(w3, blockexplorer, tx_event)
        time.sleep(1 * 60 + 10)
        agent.detect_unverified_contract_creation(
            w3, blockexplorer, wait_time=1, infinite=False)
        assert len(agent.FINDINGS_CACHE) == 0, "should have 0 finding"
