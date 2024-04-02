import agent
from forta_bot import FindingSeverity, create_transaction_event
from constants import SWFT_SWAP_ADDRESS
from web3_mock import Web3Mock, NEW_CONTRACT
from web3 import AsyncWeb3
import pytest
from unittest.mock import patch
import timeit

w3 = Web3Mock()
w3.to_checksum_address = AsyncWeb3.to_checksum_address
real_w3 = AsyncWeb3.AsyncHTTPProvider

class TestSwftSwapFundingBot:

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_transfer_to_contract(self, mocker):
        await agent.initialize()
        # Contract passed in transaction.data
        tx_event = create_transaction_event(
            transaction =  {
                'hash': "0",
                'to': SWFT_SWAP_ADDRESS[1],
                'from': "0x56f879e6586bfacafd5219207a33cae1dace7c58",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b0000000000000000000000000000000000000000000000000009f5990dc1c5000'
            },
            block = {
                'number': 1,
                'transactions': [] 
            },
            chain_id = 1                   
        )

        findings = await agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the to is a contract"

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_not_transfer_from_swft_swap(self, mocker):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': NEW_CONTRACT,
                'from': "0x56f879e6586bfacafd5219207a33cae1dace7c58",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b0000000000000000000000000000000000000000000000000009f5990dc1c5000'
            },
            block = {
                'number': 1,
                'transactions': [] 
            },
            chain_id=1
        )

        findings = await agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the to is not SWFT Swap"

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_transfer_from_swft_swap_to_new_account(self, mocker):
        await agent.initialize()
        # New EOA passed in transaction.data
        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': SWFT_SWAP_ADDRESS[1],
                'from': "0x56f879e6586bfacafd5219207a33cae1dace7c58",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b8000000000000000000000000000000000000000000000000009f5990dc1c5000'
            },
            block = {
                'number': 1,
                'transactions': [] 
            },    
            chain_id=1  
        )

        findings = await agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-SWFT-SWAP-NEW-ACCOUNT", "This is a tx from SWFT Swap to a new account"
        assert findings[0].severity == FindingSeverity.Medium, "Severity should be medium"

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_low_value_transfer_from_swft_swap(self, mocker):
        await agent.initialize()
        # Low value passed in transaction.logs.data
        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': SWFT_SWAP_ADDRESS[1],
                'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b9000000000000000000000000000000000000000000000000009f5990dc1c5000'

            },
            block = {
                'number': 1,
                'transactions': [] 
            },
            chain_id=1
        )

        findings = await agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-SWFT-SWAP-LOW-AMOUNT", "This is a low value transfer from SWFT Swap"
        assert findings[0].severity == FindingSeverity.Low, "Severity should be low"

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_high_value_transfer_from_swft_swap(self, mocker):
        await agent.initialize()
        # High value passed in transaction.logs.data
        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': SWFT_SWAP_ADDRESS[1],
                'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b9000000000000000000000000000000000000000000000000006397fa8991b2000'

            },
            block = {
                'number': 1,
                'transactions': [] 
            },
            chain_id=1
        )

        findings = await agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - It is to an 'old' address and is over the threshold."
