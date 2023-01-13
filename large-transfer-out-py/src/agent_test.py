from forta_agent import create_transaction_event, FindingSeverity, get_json_rpc_url
import timeit
import agent
from web3 import Web3
from web3_mock import Web3Mock, ADDRESS_WITH_LARGE_BALANCE, ADDRESS_WITHOUT_LARGE_BALANCE, CURRENT_BLOCK, OLDER_CURRENT_BLOCK

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

class TestLargeTransferOut:
    
    def test_large_transfer_no_alert(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4",
                'from': ADDRESS_WITH_LARGE_BALANCE,
                'value': "50000000000000000000"
            },
            'block': {
                'number': CURRENT_BLOCK
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_suspicious_native_transfers(w3, tx_event)
        assert len(findings) == 0, "this should have not triggered a finding as the account had assets 1 day ago"

    def test_preformance(self):
        agent.initialize()

        global tx_event
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4",
                'from': ADDRESS_WITH_LARGE_BALANCE,
                'value': "50000000000000000000"
            },
            'block': {
                'number': CURRENT_BLOCK
            },
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
        processing_time_ms = timeit.timeit('agent.detect_suspicious_native_transfers(w3, tx_event)', number=1, globals=globals()) * 1000
        assert processing_time_ms < 40, "processing time should be less than 43ms"

        processing_runs = 1000
        processing_time_avg_ms = timeit.timeit('agent.detect_suspicious_native_transfers(w3, tx_event)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        assert processing_time_avg_ms < 40, "processing time should be less than 43ms. If not, this bot is unlikely to keep up with fast chains, like Polygon"


    def test_gera_coin_attacker(self):
        agent.initialize()

        tx = real_w3.eth.get_transaction('0x39ed9312dabfe228ab03659192540da18b97f89eb7b89abaa9a6da03011e9668')
        
        tx_event = create_transaction_event({
            'transaction': {
                'hash': tx.hash,
                'to': tx.to,
                'from': tx['from'],
                'value': tx.value
            },
            'block': {
                'number': tx.blockNumber
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_suspicious_native_transfers(real_w3, tx_event)
        assert len(findings) == 1, "the gera coin attacker tx should have been detected"

    def test_large_transfer_alert(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4",
                'from': ADDRESS_WITHOUT_LARGE_BALANCE,
                'value': "50000000000000000000"
            },
            'block': {
                'number': CURRENT_BLOCK
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_suspicious_native_transfers(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding as account obtained assets within the last day"

    