from forta_agent import create_transaction_event, get_json_rpc_url
from web3 import Web3
import timeit
import agent
from web3_mock import Web3Mock, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD
from blockexplorer_mock import BlockExplorerMock
from blockexplorer import BlockExplorer

w3 = Web3Mock()
blockexplorer = BlockExplorerMock(1)


class TestPositiveReputation:
    def test_initialize(self):
        agent.initialize()
        assert True, "Bot didnt successfully initialize"

    def test_perf_combination_alert(self):
        global w3_real
        global blockexplorer_real
        w3_real = Web3(Web3.HTTPProvider(get_json_rpc_url()))
        blockexplorer_real = BlockExplorer(w3_real.eth.chain_id)

        agent.initialize()

        global tx_event
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': "0x378dcff8e6be1778b04f5712d686517bb6a01927",
                'value': 0,
                'to': "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
                'nonce': 500,
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

        # local testing reveals an avg processing time of 900, which results in the following sharding config:
        # Ethereum: 12s, 150 -> 80ms - 11
        # BSC: 3s, 70 -> 43ms - 21
        # Polygon: 2s, 50 -> 40ms - 21
        # Avalanche: 2s, 5 -> 400ms - 3
        # Arbitrum: 1s, 5 -> 200ms - 5
        # Optimism: 24s, 150 -> 160ms - 6
        # Fantom: 1s, 5 -> 200ms - 5

        processing_runs = 10
        processing_ms_avg = timeit.timeit('agent.detect_positive_reputation(w3_real, blockexplorer_real, tx_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
       
        assert (processing_ms_avg) < (900), f"""processing time should be less than 43ms based but was {processing_ms_avg}ms"""
        

    def test_detect_positive_reputation(self):
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_OLD,
                'value': 0,
                'to': "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
                'nonce': 500,
            },
            'block': {
                'number': 0
            },
            'logs': [],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 1, "Bot didnt successfully detect positive reputation"

    def test_detect_positive_reputation_cache(self):
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_OLD,
                'value': 0,
                'to': "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
                'nonce': 500,
            },
            'block': {
                'number': 0
            },
            'logs': [],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 1, "Bot didnt successfully detect positive reputation"

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 0, "Bot should not have emitted an alert again"

    def test_detect_positive_reputation_too_new(self):
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_NEW,
                'value': 0,
                'to': "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
                'nonce': 499,
            },
            'block': {
                'number': 0
            },
            'logs': [],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_positive_reputation(w3, blockexplorer, tx_event)
        assert len(findings) == 0, "Bot incorrectly detected positive reputation"
