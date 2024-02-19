import agent
from forta_bot import create_transaction_event, FindingSeverity
from web3_mock import Web3Mock, NEW_EOA, OLD_EOA, NEW_CONTRACT
from constants import UNION_CHAIN_ADDRESS
from unittest.mock import patch
import pytest

w3 = Web3Mock()

class TestUnionChainFundingBot:
    
    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_transfer_to_contract(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': NEW_CONTRACT,
                'from': UNION_CHAIN_ADDRESS,
                'value': "1000000000000000000"
            },
            block = {
                'number': 1
            },
            logs = [],
            chain_id = 1
        )

        findings = await agent.detect_union_chain_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the to is a contract"


    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_not_transfer_from_union_chain(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': NEW_EOA,
                'from': OLD_EOA,
                'value': "1000000000000000000"
            },
            block = {
                'number': 1
            },
            logs = [],
            chain_id = 1
        )

        findings = await agent.detect_union_chain_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the from is not Union Chain"


    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_transfer_from_union_chain_to_new_account(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': NEW_EOA,
                'from': UNION_CHAIN_ADDRESS,
                'value': "100000000000000000"
            },
            block = {
                'number': 1
            },
            logs = [],
            chain_id = 1
        )

        findings = await agent.detect_union_chain_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-UNION-CHAIN-NEW-ACCOUNT", "This is a tx from Union Chain to a new account"
        assert findings[0].severity == FindingSeverity.Medium, "Severity should be medium"


    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_low_value_transfer_from_union_chain(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': OLD_EOA,
                'from': UNION_CHAIN_ADDRESS,
                'value': "3000000000000000"
            },
            block = {
                'number': 1
            },
            logs = [],
            chain_id = 1
        )

        findings = await agent.detect_union_chain_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-UNION-CHAIN-LOW-AMOUNT", "This is a low value transfer from Union Chain"
        assert findings[0].severity == FindingSeverity.Low, "Severity should be low"

    
    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_high_value_transfer_from_union_chain(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': OLD_EOA,
                'from': UNION_CHAIN_ADDRESS,
                'value': "300000000000000000"
            },
            block = {
                'number': 1
            },
            logs = [],
            chain_id = 1
        )

        findings = await agent.detect_union_chain_funding(w3, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - It is to an address that has sent a transaction and is over the threshold."
