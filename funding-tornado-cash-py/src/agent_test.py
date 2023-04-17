from forta_agent import FindingSeverity, create_transaction_event, EntityType

import agent
from forta_agent import Label, get_json_rpc_url
from constants import TORNADO_CASH_ADDRESSES, TORNADO_CASH_WITHDRAW_TOPIC, TORNADO_CASH_ADDRESSES_HIGH
from web3_mock import EOA_ADDRESS_TC,EOA_ADDRESS_NEW, EOA_ADDRESS_OLD, Web3Mock
from web3 import Web3
import timeit

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
        

class TestTornadoCashFunding:

    def test_funding_new_account_perf_test(self):
        global real_w3
        agent.initialize()

        global tc_funding_tx_event
        tc_funding_tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 100,
                'to': EOA_ADDRESS_NEW,
            },
            'block': {
                'number': 0
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_NEW[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660"
                 }
            ],
            'receipt': {
                'logs': []}
        })

        global normal_funding_tx_event
        normal_funding_tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_OLD,
                'value': 100,
                'to': EOA_ADDRESS_NEW,
            },
            'block': {
                'number': 0
            },
            'logs': [],
            'receipt': {
                'logs': []}
        })
        
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
        
        # we're assuming 1% of tx will contain a tc funding event
        # so our target for polygon is 1 tx with a tc funding and 99 without tc funding

        processing_runs = 10
        processing_time_normal_funding_avg_ms = timeit.timeit('agent.detect_funding(real_w3, normal_funding_tx_event)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        
        processing_time_tc_funding_avg_ms = timeit.timeit('agent.detect_funding(real_w3, tc_funding_tx_event)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        assert (processing_time_normal_funding_avg_ms * 0.99 + processing_time_tc_funding_avg_ms * 0.01)/2 < 125, f"processing time should be less than 125ms based on the existing sharding config, but is {(processing_time_normal_funding_avg_ms * 0.01 + processing_time_tc_funding_avg_ms * 0.99)/2}, normal: {processing_time_normal_funding_avg_ms}, tc: {processing_time_tc_funding_avg_ms} If not, this bot is unlikely to keep up with fast chains, like Polygon"


    def test_funding_new_account(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 100,
                'to': EOA_ADDRESS_NEW,
            },
            'block': {
                'number': 0
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_NEW[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660"
                 }
            ],
            'receipt': {
                'logs': []}
        })
        
        findings = agent.detect_funding(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-TORNADO-CASH"
        assert findings[0].severity == FindingSeverity.Low

    def test_funding_old_account(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 1000,
                'to': EOA_ADDRESS_NEW,
            },
            'block': {
                'number': 0
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_OLD[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660"
                 }
            ],
            'receipt': {
                'logs': []}
        })
        
        findings = agent.detect_funding(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"

    def test_funding_high_amount(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_TC,
                'value': 10000,
                'to': EOA_ADDRESS_NEW,
            },
            'block': {
                'number': 0
            },
            'logs': [
                {'address': TORNADO_CASH_ADDRESSES_HIGH[1][0],
                 'topics': [TORNADO_CASH_WITHDRAW_TOPIC],
                 'data': f"0x000000000000000000000000{EOA_ADDRESS_NEW[2:].lower()}1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660"
                 }
            ],
            'receipt': {
                'logs': []}
        })
        
        findings = agent.detect_funding(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-TORNADO-CASH-HIGH"
        assert findings[0].severity == FindingSeverity.Info

        assert findings[0].metadata["anomaly_score"] == 0.5, "should have anomaly score of 0.5"
        assert findings[0].labels[0].toDict()["entity"] == "0xA1B4355Ae6b39bb403Be1003b7D0330C811747DB", "should have EOA address as label"
        assert findings[0].labels[0].toDict()["entity_type"] == EntityType.Address, "should have label_type address"
        assert findings[0].labels[0].toDict()["label"] == 'benign', "should have benign as label"
        assert findings[0].labels[0].toDict()["confidence"] == 0.1, "should have 0.1 as label confidence"

