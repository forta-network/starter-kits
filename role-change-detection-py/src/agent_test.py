import agent
from forta_agent import get_json_rpc_url
from forta_bot import create_transaction_event
from unittest.mock import patch
import pytest
from web3 import AsyncWeb3
from web3_mock import *
from blockexplorer_mock import BlockExplorerMock
from blockexplorer import BlockExplorer
import time

w3 = Web3Mock()
blockexplorer = BlockExplorerMock(w3.eth.chain_id)
real_w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(get_json_rpc_url()))
real_blockexplorer = BlockExplorer(real_w3.eth.chain_id)

async def async_timeit(func, *args, **kwargs):
    start_time = time.time()
    await func(*args, **kwargs)
    end_time = time.time()
    return (end_time - start_time) * 1000  # Return time in milliseconds

class TestRoleChangeAgent:

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_agent_latency(self, mocker):

        global real_w3
        agent.initialize()

        # Chain: Blocktime, Number of Tx -> Avg processing time in ms target
        # Ethereum: 12s, 150 -> 80ms
        # BSC: 3s, 70 -> 43ms
        # Polygon: 2s, 50 -> 40ms
        # Avalanche: 2s, 5 -> 400ms
        # Arbitrum: 1s, 5 -> 200ms
        # Optimism: 24s, 150 -> 160ms
        # Fantom: 1s, 5 -> 200ms

        global transaction_not_to_contract
        transaction_not_to_contract = create_transaction_event(
            transaction = {
                'hash': "0x4a419b16152cc6513db84bdfb94818827ef8e64c2bc52f9a95f960c47ef02817",
                'from': "0x5b7d833a4aa182bddd754db797d43d3c29c171a0",
                'value': 100,
                'to': "0xb2880739e3bd3f535d38760cd8f2ee058737341b",
            },
            block = {
                'number': 1
            },
            chain_id = 1
        )

        global transaction_without_role_change
        transaction_without_role_change = create_transaction_event(
            transaction = {
                'hash': "0x46b6a79429f93b7c280d3962eb536d58ab9c2d174f19da42bc107f7aa15e91c4",
                'from': "0x5fede37f5a4d004b7a7b2f574587dc04b1627b65",
                'value': 100,
                'to': "0xf164fc0ec4e93095b804a4795bbe1e041497b92a",
            },
            block = {
                'number': 1
            },
            chain_id = 1
        )

        global transaction_with_role_change
        transaction_with_role_change = create_transaction_event(
            transaction = {
                'hash': "0x30a332902920cb6886281f6d28abfa5775559647eb7288e7cc00763fe4427f7b",
                'from': "0xfdf8be775bb5e2ba1983dc7b26a655321502e104",
                'value': 1381970000000000,
                'to': "0x1559fa1b8f28238fd5d76d9f434ad86fd20d1559",
            },
            block = {
                'number': 1
            },
            chain_id = 1
        )

        processing_runs = 10

        processing_time_not_to_contract = await async_timeit(agent.detect_role_change, real_w3, real_blockexplorer, transaction_not_to_contract) / processing_runs
        processing_time_without_role_change = await async_timeit(agent.detect_role_change, real_w3, real_blockexplorer, transaction_without_role_change) / processing_runs
        processing_time_with_role_change = await async_timeit(agent.detect_role_change, real_w3, real_blockexplorer, transaction_with_role_change) / processing_runs

        eth_shard_count = 18
        polygon_shard_count = 28
        bsc_shard_count = 24
        default_shard_count = 8

        avg_processing_time = (processing_time_not_to_contract * 0.33 + processing_time_without_role_change * 0.66 + processing_time_with_role_change * 0.01)

        assert (avg_processing_time/eth_shard_count) < 80, f"ETH -> Avg processing: {avg_processing_time}, Avg processing per shard: {avg_processing_time/eth_shard_count}"
        assert (avg_processing_time/polygon_shard_count) < 40, f"MATIC -> Avg processing: {avg_processing_time}, Avg processing per shard: {avg_processing_time/polygon_shard_count}"
        assert (avg_processing_time/bsc_shard_count) < 43, f"BSC -> Avg processing: {avg_processing_time}, Avg processing per shard: {avg_processing_time/bsc_shard_count}"
        assert (avg_processing_time/default_shard_count) < 160, f"Default -> Avg processing: {avg_processing_time}, Avg processing per shard: {avg_processing_time/default_shard_count}"


    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_transfer_without_role_change(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'to': VERIFIED_CONTRACT,
                'from': NEW_EOA,
                'hash': "0x8fc91a50a2614d323864655c2473ec19e58cb356a9f1d391888c472476c749f7"
            },
            block = {
                'number': 1
            },
            logs = [],
            chain_id = 1
        )

        findings = await agent.detect_role_change(w3, blockexplorer, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - no role change"


    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_transfer_to_eoa(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'to': NEW_EOA,
                'from': OLD_EOA,
                'hash': "0x8fc91a50a2614d323864655c2473ec19e58cb356a9f1d391888c472476c749f7"
            },
            block = {
                'number': 1
            },
            logs = [],
            chain_id = 1
        )

        findings = await agent.detect_role_change(w3, blockexplorer, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - not to a contract"
