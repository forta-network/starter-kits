from forta_agent import FindingSeverity, FindingType, create_transaction_event

import agent
from etherscan_mock import EtherscanMock
from web3_mock import (CONTRACT_NO_ADDRESS, CONTRACT_WITH_ADDRESS, EOA_ADDRESS,
                       Web3Mock)

w3 = Web3Mock()
etherscan = EtherscanMock()


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

    def test_detect_unverified_contract_with_unverified_contract(self):
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 9,
            },
            'block': {
                'number': 0
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

        findings = agent.detect_unverified_contract_creation(w3, etherscan, tx_event)
        assert len(findings) == 1, "should have 1 finding"
        finding = next((x for x in findings if x.alert_id == 'UNVERIFIED-CODE-CONTRACT-CREATION'), None)
        assert finding.severity == FindingSeverity.Medium
        assert finding.type == FindingType.Suspicious
        assert finding.description == f'{EOA_ADDRESS} created contract 0x728ad672409DA288cA5B9AA85D1A55b803bA97D7'
        assert len(finding.metadata) > 0

    def test_detect_unverified_contract_with_verified_contract(self):
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,  # verified contract
            },
            'block': {
                'number': 0
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

        findings = agent.detect_unverified_contract_creation(w3, etherscan, tx_event)
        assert len(findings) == 0, "should have 0 finding"

    def test_detect_unverified_contract_call_only(self):
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 9,  # unverified contract
            },
            'block': {
                'number': 0
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

        findings = agent.detect_unverified_contract_creation(w3, etherscan, tx_event)
        assert len(findings) == 0, "should have 0 finding"
