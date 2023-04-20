from forta_agent import create_transaction_event, FindingSeverity, EntityType
from unittest.mock import patch
import agent
from findings import SuspiciousContractFindings
from constants import TORNADO_CASH_ADDRESSES
from web3_mock import Web3Mock, CONTRACT_NO_ADDRESS, CONTRACT_WITH_ADDRESS, EOA_ADDRESS


w3 = Web3Mock()


class TestSuspiciousContractAgent:
    def test_is_contract_eoa(self):
        assert not agent.is_contract(
            w3, EOA_ADDRESS), "EOA shouldn't be identified as a contract"

    def test_is_contract_contract(self):
        assert agent.is_contract(
            w3, CONTRACT_NO_ADDRESS), "Contract should be identified as a contract"

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

    def test_update_tornado_cash_funded_accounts(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'action': {
                     'to': EOA_ADDRESS,
                     'from': TORNADO_CASH_ADDRESSES[0],
                     'value': 1,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        agent.update_tornado_cash_funded_accounts(w3, tx_event)
        assert EOA_ADDRESS in agent.TORNADO_CASH_FUNDED_ACCOUNTS, "this address was just funded by tornado cash"

    def test_calc_contract_address(self):
        contract_address = agent.calc_contract_address(w3, EOA_ADDRESS, 9)
        assert contract_address == "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7", "should be the same contract address"

    def test_finding_tornado_cash_and_contract_creation(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'action': {
                     'to': EOA_ADDRESS,
                     'from': TORNADO_CASH_ADDRESSES[0],
                     'value': 1,
                 }
                 },
                {'type': 'create',
                 'action': {
                     'from': EOA_ADDRESS,
                     'value': 1,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_suspicious_contract_creations(w3, tx_event)
        assert len(findings) > 0, "this should have triggered a finding"
        finding = next((x for x in findings if x.alert_id ==
                       'SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH'), None)
        assert finding.severity == FindingSeverity.High

        assert findings[0].labels[0].toDict(
        )["entity"] == EOA_ADDRESS, "should have EOA address as label"
        assert findings[0].labels[0].toDict(
        )["entityType"] == EntityType.Address, "should have label_type address"
        assert findings[0].labels[0].toDict(
        )["label"] == 'attacker', "should have attacker as label"
        assert findings[0].labels[0].toDict(
        )["confidence"] == 0.3, "should have 0.3 as label confidence"
        assert findings[0].labels[1].toDict(
        )["entity"] == '0xD56A0d6fe38cD6153C7B26ECE11b405BCADfF253', "should have contract address as label"
        assert findings[0].labels[1].toDict(
        )["label"] == 'attacker_contract', "should have attacker as label"
        assert findings[0].labels[1].toDict(
        )["confidence"] == 0.3, "should have 0.3 as label confidence"
        assert findings[0].labels[1].toDict(
        )["entityType"] == EntityType.Address, "should have label_type address"

    def test_finding_tornado_cash_and_no_contract_creation(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
                'to': EOA_ADDRESS,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'action': {
                     'to': EOA_ADDRESS,
                     'from': TORNADO_CASH_ADDRESSES[0],
                     'value': 1,
                 }
                 },
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_suspicious_contract_creations(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"

    def test_finding_not_tornado_cash_and_contract_creation_eoa_creation(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_suspicious_contract_creations(w3, tx_event)
        assert len(findings) > 0, "this should have triggered a finding"
        finding = next((x for x in findings if x.alert_id ==
                       'SUSPICIOUS-CONTRACT-CREATION'), None)
        assert finding.severity == FindingSeverity.Low

    def test_finding_not_tornado_cash_and_contract_creation_trace(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'to': '0x0000000000000000000000000000000000000000',
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'create',
                 'action': {
                     'from': EOA_ADDRESS,
                     'value': 1,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_suspicious_contract_creations(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        finding = next((x for x in findings if x.alert_id ==
                       'SUSPICIOUS-CONTRACT-CREATION'), None)
        assert finding.severity == FindingSeverity.Low

    def test_finding_not_tornado_cash_and_no_contract_creation_empty_set(self, mocker):
        agent.initialize()

        contained_addresses = set()
        finding = SuspiciousContractFindings.suspicious_contract_creation_tornado_cash(
            "from_address", "contract_address", contained_addresses, 1)
        assert finding.severity == FindingSeverity.High

    def test_finding_not_tornado_cash_and_no_contract_creation(self):
        agent.initialize()

        contained_addresses = {"address1", "address2"}
        finding = SuspiciousContractFindings.suspicious_contract_creation_tornado_cash(
            "from_address", "contract_address", contained_addresses, 1)
        assert finding.severity == FindingSeverity.High
        assert finding.metadata["address_contained_in_created_contract_1"] == "address1"
        assert finding.metadata["address_contained_in_created_contract_2"] == "address2"
