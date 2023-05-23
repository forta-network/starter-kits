from unittest.mock import patch
from web3 import Web3
import timeit
from forta_agent import create_transaction_event, EntityType, get_json_rpc_url
import agent
from web3_mock import Web3Mock, NEW_EOA, OLD_EOA, NEW_CONTRACT

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


class TestDEXFunding:
    def test_cex_funding_perf_test(self):
        global real_w3
        agent.initialize()

        global real_w3
        tx = real_w3.eth.get_transaction(
            '0x11aa33cf560a880cdc88785306d3f266aab0f22dd7ded7ddc99480ec89e9d634')

        global cex_funding_tx_event
        cex_funding_tx_event = create_transaction_event({
            'transaction': {
                'hash': '0x11aa33cf560a880cdc88785306d3f266aab0f22dd7ded7ddc99480ec89e9d634',
                'to': tx.to,
                'from': tx['from'],
                'value': tx.value
            },
            'block': {
                'number': tx.blockNumber
            },
            'receipt': {
                'logs': []
            }
        })
        
        tx = real_w3.eth.get_transaction(
            '0xd3420bc1a3ac57186738be77d326d342c6f196ff054867b5b97e31aaedaa4095')

        global new_eoa_funding_tx_event
        new_eoa_funding_tx_event = create_transaction_event({
            'transaction': {
                'hash': '0xd3420bc1a3ac57186738be77d326d342c6f196ff054867b5b97e31aaedaa4095',
                'to': tx.to,
                'from': tx['from'],
                'value': tx.value
            },
            'block': {
                'number': tx.blockNumber
            },
            'receipt': {
                'logs': []
            }
        })

        tx = real_w3.eth.get_transaction(
            '0xb83d4f595c27755b601cea42036693d96fb60de181d19870e4a7459ff2fa3000')

        global other_tx_event
        other_tx_event = create_transaction_event({
            'transaction': {
                'hash': '0xb83d4f595c27755b601cea42036693d96fb60de181d19870e4a7459ff2fa3000',
                'to': tx.to,
                'from': tx['from'],
                'value': tx.value
            },
            'block': {
                'number': tx.blockNumber
            },
            'receipt': {
                'logs': []
            }
        })
        

        # Chain: Blocktime, Number of Tx -> Avg processing time in ms target
        # Ethereum: 12s, 150 -> 80ms
        # BSC: 3s, 70 -> 43ms
        # Polygon: 2s, 50 -> 40ms
        # Avalanche: 2s, 5 -> 400ms
        # Arbitrum: 1s, 5 -> 200ms
        # Optimism: 24s, 150 -> 160ms
        # Fantom: 1s, 5 -> 200ms

        # local testing reveals an avg processing time of 110ms, which results in the following sharding config:
        # Ethereum: 12s, 150 -> 80ms - 2
        # BSC: 3s, 70 -> 43ms - 3
        # Polygon: 2s, 50 -> 40ms - 3
        # Avalanche: 2s, 5 -> 400ms - 1
        # Arbitrum: 1s, 5 -> 200ms - 1
        # Optimism: 24s, 150 -> 160ms - 1
        # Fantom: 1s, 5 -> 200ms - 1

        # we're assuming 0,001% of tx will contain a cex funding transaction to a new EOA

        processing_runs = 10
        processing_time_dex_funding_tx_avg_ms = timeit.timeit(
            'agent.detect_dex_funding(real_w3, cex_funding_tx_event)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        
        processing_time_new_eoa_funding_tx_avg_ms = timeit.timeit(
            'agent.detect_dex_funding(real_w3, new_eoa_funding_tx_event)', number=processing_runs, globals=globals()) * 1000 / processing_runs

        processing_time_other_tx_avg_ms = timeit.timeit(
            'agent.detect_dex_funding(real_w3, other_tx_event)', number=processing_runs, globals=globals()) * 1000 / processing_runs
                
        assert (processing_time_dex_funding_tx_avg_ms * 0.001 + processing_time_new_eoa_funding_tx_avg_ms * 0.05 + processing_time_other_tx_avg_ms * 0.949) / \
            3 < 110, "processing time should be less than 230ms."

    def test_not_transfer_to_cex(self):
        agent.initialize()

        tx_event = create_transaction_event(
            {
                "transaction": {
                    "hash": "0",
                    "to": NEW_EOA,
                    "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e0000",
                    "value": "1000000000000000000",
                },
                "block": {"number": 1},
                "receipt": {"logs": []},
            }
        )

        findings = agent.detect_dex_funding(w3, tx_event)
        assert (
            len(findings) == 0
        ), "this should have not triggered a finding as the from is not a CEX"

    def test_transfer_to_contract(self):
        agent.initialize()

        tx_event = create_transaction_event(
            {
                "transaction": {
                    "hash": "0",
                    "to": NEW_CONTRACT,
                    "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e0000",
                    "value": "1000000000000000000",
                },
                "block": {"number": 1},
                "receipt": {"logs": []},
            }
        )

        findings = agent.detect_dex_funding(w3, tx_event)
        assert (
            len(findings) == 0
        ), "this should have not triggered a finding is to a contract"

    def test_transfer_to_old_eoa(self):
        agent.initialize()

        tx_event = create_transaction_event(
            {
                "transaction": {
                    "hash": "0",
                    "to": OLD_EOA,
                    "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e0000",
                    "value": "1000000000000000000",
                },
                "block": {"number": 1},
                "receipt": {"logs": []},
            }
        )

        findings = agent.detect_dex_funding(w3, tx_event)
        assert (
            len(findings) == 0
        ), "this should have not triggered a finding is to an old EOA"

    def test_transfer_excessive_amount(self):
        agent.initialize()

        tx_event = create_transaction_event(
            {
                "transaction": {
                    "hash": "0",
                    "to": NEW_EOA,
                    "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e0000",
                    "value": "3000000000000000000",
                },
                "block": {"number": 1},
                "receipt": {"logs": []},
            }
        )

        findings = agent.detect_dex_funding(w3, tx_event)
        assert (
            len(findings) == 0
        ), "this should have not triggered a finding as funding amount is too large"

    @patch("src.findings.calculate_alert_rate", return_value=1.0)
    def test_cex_funding(self, mocker):
        agent.initialize()

        tx_event = create_transaction_event(
            {
                "transaction": {
                    "hash": "0",
                    "to": NEW_EOA,
                    "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f",
                    "value": "1000000000000000000",
                },
                "block": {"number": 1},
                "receipt": {"logs": []},
            }
        )

        findings = agent.detect_dex_funding(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"

        assert (
            findings[0].metadata["anomaly_score"] == 1.0
        ), "should have anomaly score of 1.0"
        assert (
            findings[0].labels[0].toDict()["entity"] == NEW_EOA
        ), "should have EOA address as label"
        assert (
            findings[0].labels[0].toDict()["entity_type"] == EntityType.Address
        ), "should have label_type address"
        assert (
            findings[0].labels[0].toDict()["label"] == "attacker"
        ), "should have attacker as label"
