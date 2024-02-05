import agent
from forta_bot import create_transaction_event, FindingSeverity, get_provider
from unittest.mock import patch
import pytest
from web3 import Web3
from src.web3_mock import Web3Mock, NEW_EOA, OLD_EOA, NEW_CONTRACT
import timeit

w3 = Web3Mock()

class TestChangeNowFundingAgent:

    # @pytest.mark.asyncio
    # async def test_agent_latency(self):

    #     global real_w3
    #     eth_provider = await get_provider({
    #         'rpc_url': "https://eth-mainnet.g.alchemy.com/v2",
    #         'rpc_key_id': "e698634d-79c2-44fe-adf8-f7dac20dd33c",
    #         'local_rpc_url': "1",
    #     })
    #     real_w3 = Web3(Web3.HTTPProvider(eth_provider))

    #     agent.initialize()

    #     # Chain: Blocktime, Number of Tx in block -> Avg processing time in ms target
    #     # Ethereum: 12s, 150 -> 80ms
    #     # Base: 2s, 12 -> 167ms

    #     # Ethereum: 12s, 150 -> 80ms - 2
    #     # Base: 2s, 12 -> 167ms - N
        
    #     # we're assuming 1% of tx will contain a tc funding event, but only 50% of tx are funding
    #     # so our target for polygon is 1 tx with a tc funding and 49 without tc funding and 50% are no funding

    #     global transaction_with_no_funding
    #     transaction_with_no_funding = create_transaction_event(
    #         transaction = {
    #             'hash': "0x4a419b16152cc6513db84bdfb94818827ef8e64c2bc52f9a95f960c47ef02817",
    #             'from': "0x5b7d833a4aa182bddd754db797d43d3c29c171a0",
    #             'value': 100,
    #             'to': "0xb2880739e3bd3f535d38760cd8f2ee058737341b",
    #         },
    #         block = {
    #             'number': 1
    #         },
    #         network_id = 1
    #     )

    #     global transaction_from_changenow_to_contract
    #     transaction_from_changenow_to_contract = create_transaction_event(
    #         transaction = {
    #             'hash': "0x4a419b16152cc6513db84bdfb94818827ef8e64c2bc52f9a95f960c47ef02817",
    #             'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
    #             'value': 100,
    #             'to': "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
    #         },
    #         block = {
    #             'number': 1
    #         },
    #         network_id = 1
    #     )

    #     global transaction_with_changenow_funding
    #     transaction_with_changenow_funding = create_transaction_event(
    #         transaction = {
    #             'hash': "0xc4af34bc84bbdda599ccf915a9c6cb62481899086767480212a4b28f4636c0f7",
    #             'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
    #             'value': 1381970000000000,
    #             'to': "0xfea89fe5d3e0d24a1f219a33e3fd3b1831cd171b",
    #         },
    #         block = {
    #             'number': 1
    #         },
    #         network_id = 1
    #     )

    #     processing_runs = 10

    #     processing_time_no_funding = (await timeit.timeit(
    #         'agent.detect_changenow_funding(real_w3, transaction_with_no_funding)', number=processing_runs, globals=globals()
    #     )) * 1000 / processing_runs

    #     processing_time_changenow_to_contract = (await timeit.timeit(
    #         'agent.detect_changenow_funding(real_w3, transaction_from_changenow_to_contract)', number=processing_runs, globals=globals()
    #     )) * 1000 / processing_runs

    #     processing_time_with_changenow_funding = (await timeit.timeit(
    #         'agent.detect_changenow_funding(real_w3, transaction_with_changenow_funding)', number=processing_runs, globals=globals()
    #     )) * 1000 / processing_runs

    #     eth_shard_count = 10
    #     polygon_shard_count = 17
    #     bsc_shard_count = 15
    #     avg_processing_time = (processing_time_no_funding * 0.90 + processing_time_changenow_to_contract * 0.09 + processing_time_with_changenow_funding * 0.01)

    #     assert (avg_processing_time/eth_shard_count) < 80, f"ETH -> Avg processing: {avg_processing_time}, Avg processing per shard: {avg_processing_time/eth_shard_count}"
    #     assert (avg_processing_time/polygon_shard_count) < 43, f"MATIC -> Avg processing: {avg_processing_time}, Avg processing per shard: {avg_processing_time/polygon_shard_count}"
    #     assert (avg_processing_time/bsc_shard_count) < 40, f"BSC -> Avg processing: {avg_processing_time}, Avg processing per shard: {avg_processing_time/bsc_shard_count}"
    
    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_transfer_to_contract(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': NEW_CONTRACT,
                'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
                'value': "1000000000000000000"
            },
            block = {
                'number': 1
            },
            network_id = 1
        )

        findings = await agent.detect_changenow_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the to is a contract"


    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_not_transfer_from_changenow(self, mocker):
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
            network_id = 1
        )

        findings = await agent.detect_changenow_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the from is not Changenow"


    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_transfer_from_changenow_to_new_account(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': NEW_EOA,
                'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
                'value': "100000000000000000"
            },
            block = {
                'number': 1
            },
            network_id = 1
        )

        findings = await agent.detect_changenow_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-CHANGENOW-NEW-ACCOUNT", "This is a tx from Changenow to a new account"
        assert findings[0].severity == FindingSeverity.Low, "Severity should be low"


    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_low_value_transfer_from_changenow(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': OLD_EOA,
                'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
                'value': "3000000000000000"
            },
            block = {
                'number': 1
            },
            network_id = 1
        )

        findings = await agent.detect_changenow_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-CHANGENOW-LOW-AMOUNT", "This is a low value transfer from Changenow"
        assert findings[0].severity == FindingSeverity.Low, "Severity should be low"

    
    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_high_value_transfer_from_changenow(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'to': OLD_EOA,
                'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
                'value': "300000000000000000"
            },
            block = {
                'number': 1
            },
            network_id = 1
        )

        findings = await agent.detect_changenow_funding(w3, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - It is to an address that has sent a transaction and is over the threshold."
