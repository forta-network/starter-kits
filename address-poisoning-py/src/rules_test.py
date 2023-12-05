from web3_mock import *
from rules import AddressPoisoningRules
from forta_agent import create_transaction_event
from web3_constants_mock import *
from unittest.mock import MagicMock

w3 = Web3Mock()
heuristic = AddressPoisoningRules()


class TestAddressPoisoningRules:

    def test_is_contract_contract(self):
        assert heuristic.is_contract(w3, CONTRACT) 


    def test_is_contract_eoa(self):
        assert heuristic.is_contract(w3, NEW_EOA) is False 

    
    def test_have_addresses_been_detected_positive(self):
        zero_value_contracts = set([NEW_EOA])
        low_value_contracts = set([])
        fake_token_contracts = set([])

        positive_case = create_transaction_event({
            'transaction': {
                'to': NEW_EOA,
                'from': CONTRACT
            }
        })
        assert heuristic.have_addresses_been_detected(
            positive_case, zero_value_contracts, low_value_contracts, fake_token_contracts
        ) == "ADDRESS-POISONING-ZERO-VALUE", "Address should be flagged as being in the zero_value_contracts"


    def test_have_addresses_been_detected_negative(self):
        zero_value_contracts = set([NEW_EOA, CONTRACT])
        low_value_contracts = set([])
        fake_token_contracts = set([])

        negative_case = create_transaction_event({
            'transaction': {
                'to': OLD_EOA,
                'from': CONTRACT
            }
        })
        assert heuristic.have_addresses_been_detected(
            negative_case, zero_value_contracts, low_value_contracts, fake_token_contracts
        ) == "", "Address should be flagged as being in the zero_value_contracts"


    def test_are_all_logs_stablecoins_positive(self):
        assert heuristic.are_all_logs_stablecoins(
            MOCK_TX_HASH_LOGS_MAPPING['0xpositive_zero']['logs'], w3.eth.chain_id
        ) >= 0.8 


    def test_are_all_logs_stablecoins_negative(self):
        assert (heuristic.are_all_logs_stablecoins(
            MOCK_TX_HASH_LOGS_MAPPING['0xnegative_zero']['logs'], 
            w3.eth.chain_id
        ) >= 0.8) is False 


    def test_are_all_logs_transfers_positive(self):
        assert heuristic.are_all_logs_transfers_or_approvals(
            MOCK_TX_HASH_LOGS_MAPPING['0xpositive_zero']['logs']
        ) is True


    def test_are_all_logs_transfers_negative(self):
        assert heuristic.are_all_logs_transfers_or_approvals(
            MOCK_TX_HASH_LOGS_MAPPING['0xnegative_zero']['logs']
        ) is False


    def test_is_zero_value_tx_positive(self):
        assert heuristic.is_zero_value_tx(
            MOCK_TX_HASH_LOGS_MAPPING['0xpositive_zero']['logs'],
            w3.eth.chain_id
        ) is True


    def test_is_zero_value_tx_negative(self):
        assert heuristic.is_zero_value_tx(
            MOCK_TX_HASH_LOGS_MAPPING['0xnegative_zero']['logs'],
            w3.eth.chain_id
        ) is False


    def test_are_tokens_using_known_symbols_positive(self):
        assert heuristic.are_tokens_using_known_symbols(
            w3, 
            MOCK_TX_HASH_LOGS_MAPPING['0xpositive_fake_token']['logs'], 
            w3.eth.chain_id
        ) is True


    def test_are_tokens_using_known_symbols_negative(self):
        assert heuristic.are_tokens_using_known_symbols(
            w3,
            MOCK_TX_HASH_LOGS_MAPPING['0xnegative_fake_token']['logs'],
            w3.eth.chain_id
        ) is False


    def test_are_tokens_minted_positive(self):
        assert heuristic.are_tokens_minted(
            MOCK_TX_HASH_LOGS_MAPPING['0x_token_mint']['logs']
        ) is True


    def test_are_tokens_minted(self):
        assert heuristic.are_tokens_minted(
            MOCK_TX_HASH_LOGS_MAPPING['0xnegative_fake_token']['logs']
        ) is False