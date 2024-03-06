import timeit
import agent
from web3 import Web3
from web3_mock import Web3Mock, ADDRESS_WITH_LARGE_BALANCE, ADDRESS_WITHOUT_LARGE_BALANCE, CURRENT_BLOCK, OLDER_CURRENT_BLOCK
from forta_agent import create_transaction_event, FindingSeverity, get_json_rpc_url, EntityType
from src.constants import SWAP_TOPICS

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
                'value': "50000000000000000000",
                'data': '0x1234'
            },
            'block': {
                'number': CURRENT_BLOCK
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_suspicious_native_transfers(w3, tx_event)
        assert len(
            findings) == 0, "this should have not triggered a finding as the account had assets 1 day ago"

    def test_preformance(self):
        agent.initialize()

        global real_w3
        tx = real_w3.eth.get_transaction(
            '0x39ed9312dabfe228ab03659192540da18b97f89eb7b89abaa9a6da03011e9668')

        global large_transfer_tx_event
        large_transfer_tx_event = create_transaction_event({
            'transaction': {
                'hash': tx.hash,
                'to': tx.to,
                'from': tx['from'],
                'value': tx.value,
                'data': '0x1234'

            },
            'block': {
                'number': tx.blockNumber
            },
            'receipt': {
                'logs': []}
        })

        tx = real_w3.eth.get_transaction(
            '0xc8a4877b4b3ed9e1cbd22bcbd8d6f6e78b8d70e96475dfa4a4b9751bf0c08a29')
        global small_transfer_tx_event
        small_transfer_tx_event = create_transaction_event({
            'transaction': {
                'hash': tx.hash,
                'to': tx.to,
                'from': tx['from'],
                'value': tx.value,
                'data': '0x1234'
            },
            'block': {
                'number': tx.blockNumber
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

        # we're assuming 10% of tx will contain a large transfer
        # so our target for polygon is 5 tx with a large transfer and 45 without large transfers

        processing_runs = 10
        processing_time_large_transfers_avg_ms = timeit.timeit(
            'agent.detect_suspicious_native_transfers(real_w3, large_transfer_tx_event)', number=processing_runs, globals=globals()) * 1000 / processing_runs

        processing_time_small_transfers_ms = timeit.timeit(
            'agent.detect_suspicious_native_transfers(real_w3, small_transfer_tx_event)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        assert (processing_time_large_transfers_avg_ms * 0.05 + processing_time_small_transfers_ms * 0.95) / \
            2 < 40, "processing time should be less than 43ms. If not, this bot is unlikely to keep up with fast chains, like Polygon"

    def test_gera_coin_attacker(self):
        agent.initialize()

        tx = real_w3.eth.get_transaction(
            '0x39ed9312dabfe228ab03659192540da18b97f89eb7b89abaa9a6da03011e9668')

        tx_event = create_transaction_event({
            'transaction': {
                'hash': tx.hash,
                'to': tx.to,
                'from': tx['from'],
                'value': tx.value,
                'data': '0x1234'
            },
            'block': {
                'number': tx.blockNumber
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_suspicious_native_transfers(real_w3, tx_event)
        assert len(
            findings) == 1, "the gera coin attacker tx should have been detected"

    def test_large_transfer_alert(self, mocker):
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4",
                'from': ADDRESS_WITHOUT_LARGE_BALANCE,
                'value': "50000000000000000000",
                'data': '0x1234'
            },
            'block': {
                'number': CURRENT_BLOCK
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_suspicious_native_transfers(w3, tx_event)
        assert len(
            findings) == 1, "this should have triggered a finding as account obtained assets within the last day"

        assert findings[0].labels[0].toDict(
        )["entity"] == ADDRESS_WITHOUT_LARGE_BALANCE, "should have EOA address as label"
        assert findings[0].labels[0].toDict(
        )["entity_type"] == EntityType.Address, "should have label_type address"
        assert findings[0].labels[0].toDict(
        )["label"] == 'attacker', "should have attacker as label"
        assert findings[0].labels[0].toDict(
        )["confidence"] == 0.3, "should have 0.3 as label confidence"

    def test_swaps(self, mocker):
        agent.initialize()
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4",
                'from': ADDRESS_WITHOUT_LARGE_BALANCE,
                'value': "50000000000000000000",
                'data': '0x1234'
            },
            'block': {
                'number': CURRENT_BLOCK
            },
            'logs': [
                {
                    'topics': [SWAP_TOPICS[0]],
                }
            ],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_suspicious_native_transfers(w3, tx_event)
        assert len(
            findings) == 0, "this should not have triggered a finding as transaction is a swap"
