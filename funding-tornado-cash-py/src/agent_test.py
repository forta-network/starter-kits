from forta_bot import FindingSeverity, create_transaction_event, EntityType
from unittest.mock import patch
import agent
import pytest
import time
from constants import TORNADO_CASH_ADDRESSES, TORNADO_CASH_WITHDRAW_TOPIC, TORNADO_CASH_ADDRESSES_HIGH
from web3_mock import EOA_ADDRESS_TC,EOA_ADDRESS_NEW, EOA_ADDRESS_OLD, Web3Mock
from web3 import Web3, AsyncWeb3

w3 = Web3Mock()
w3.to_checksum_address = Web3.to_checksum_address
real_w3 = AsyncWeb3.AsyncHTTPProvider

async def async_timeit(func, *args, **kwargs):
    start_time = time.time()
    await func(*args, **kwargs)
    end_time = time.time()
    return (end_time - start_time) * 1000  # Return time in milliseconds

class TestTornadoCashFunding:
    @pytest.mark.asyncio
    async def test_funding_new_account_perf_test(self):
        global real_w3
        await agent.initialize()

        global tc_funding_tx_event
        tc_funding_tx_event = create_transaction_event(
            transaction= {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 100,
                'to': EOA_ADDRESS_NEW,
            },
            block={
                    'number': 0
            },
            chain_id=1,
            logs = [
                {
                 'address': TORNADO_CASH_ADDRESSES[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_NEW[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660",
                }
            ],
            )

        global normal_funding_tx_event
        normal_funding_tx_event = create_transaction_event (
            transaction= {
                'hash': "0",
                'from': EOA_ADDRESS_OLD,
                'value': 100,
                'to': EOA_ADDRESS_NEW,
            },
            block={
                    'number': 0
            },
            chain_id=1,
            logs= []
        )

        global no_funding_tx_event
        no_funding_tx_event = create_transaction_event (
            transaction= {
                'hash': "0",
                'from': EOA_ADDRESS_OLD,
                'value': 0,
                'to': EOA_ADDRESS_NEW,
            },
            block={
                    'number': 0
            },
            chain_id=1,
            logs= []
        )

        # Chain: Blocktime, Number of Tx -> Avg processing time in ms target
        # Ethereum: 12s, 150 -> 80ms
        # BSC: 3s, 70 -> 43ms
        # Polygon: 2s, 50 -> 40ms
        # Avalanche: 2s, 5 -> 400ms
        # Arbitrum: 1s, 5 -> 200ms
        # Optimism: 24s, 150 -> 160ms
        # Fantom: 1s, 5 -> 200ms

        # local testing reveals an avg processing time of 125, which results in the following sharding config:
        # Ethereum: 12s, 150 -> 80ms - 2
        # BSC: 3s, 70 -> 43ms - 3
        # Polygon: 2s, 50 -> 40ms - 4
        # Avalanche: 2s, 5 -> 400ms - 1
        # Arbitrum: 1s, 5 -> 200ms - 1
        # Optimism: 24s, 150 -> 160ms - 1
        # Fantom: 1s, 5 -> 200ms - 1

        # we're assuming 1% of tx will contain a tc funding event, but only 50% of tx are funding
        # so our target for polygon is 1 tx with a tc funding and 49 without tc funding and 50% are no funding

        processing_runs = 10
        processing_time_normal_funding_avg_ms = await async_timeit(agent.detect_funding, real_w3, normal_funding_tx_event) / processing_runs
        processing_time_no_funding_avg_ms = await async_timeit(agent.detect_funding, real_w3, normal_funding_tx_event) / processing_runs
        processing_time_tc_funding_avg_ms = await async_timeit(agent.detect_funding, real_w3, normal_funding_tx_event) / processing_runs
        assert (processing_time_normal_funding_avg_ms * 0.49 + processing_time_no_funding_avg_ms * 0.50 + processing_time_tc_funding_avg_ms * 0.01)/2 < 125, f"processing time should be less than 125ms based on the existing sharding config, but is {(processing_time_normal_funding_avg_ms * 0.49 + processing_time_no_funding_avg_ms * 0.50 + processing_time_tc_funding_avg_ms * 0.01)/2}, normal: {processing_time_normal_funding_avg_ms}, tc: {processing_time_tc_funding_avg_ms}, no funding: {processing_time_no_funding_avg_ms} If not, this bot is unlikely to keep up with fast chains, like Polygon"

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_funding_new_account(self, mocker):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 100,
                'to': EOA_ADDRESS_NEW,
            },
            block= {
                'number': 0
            },
            chain_id=1,
            logs = [
                {'address': TORNADO_CASH_ADDRESSES[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_NEW[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660"
                 }
            ]
        )

        findings = await agent.detect_funding(w3, tx_event)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-TORNADO-CASH"
        assert findings[0].severity == FindingSeverity.Low

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_funding_old_account(self, mocker):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction= {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 1000,
                'to': EOA_ADDRESS_NEW,
            },
            block= {
                'number': 0
            },
            chain_id=1,
            logs= [
                {'address': TORNADO_CASH_ADDRESSES[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_OLD[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660"
                 }
            ]
        )

        findings = await agent.detect_funding(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    @patch("findings.calculate_alert_rate", return_value=0.5)
    async def test_funding_high_amount(self, mocker, mocker2):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 10000,
                'to': EOA_ADDRESS_NEW,
            },
            block = {
                'number': 0
            },
            chain_id=1,
            logs = [
                {'address': TORNADO_CASH_ADDRESSES_HIGH[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_NEW[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660"
                 }
            ]
        )

        findings = await agent.detect_funding(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-TORNADO-CASH-HIGH"
        assert findings[0].severity == FindingSeverity.Info
        assert findings[0].metadata["anomaly_score"] == "0.5", "should have anomaly score of 0.5"

        assert findings[0].labels[0].entity == "0xA1B4355Ae6b39bb403Be1003b7D0330C811747DB", "should have EOA address as label"
        assert findings[0].labels[0].entity_type == EntityType.Address, "should have label_type address"
        assert findings[0].labels[0].label == 'benign', "should have benign as label"
        assert findings[0].labels[0].confidence == 0.1, "should have 0.1 as label confidence"
