from hexbytes import HexBytes
import agent
from forta_agent import FindingSeverity, create_transaction_event, Web3, get_json_rpc_url
from src.constants import SWFT_SWAP_ADDRESS
from src.web3_mock import Web3Mock, NEW_EOA, OLD_EOA, NEW_CONTRACT
import timeit

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

class TestSwftSwapFundingBot:

    def test_transfer_to_contract(self):
        agent.initialize()
        # Contract passed in transaction.data
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': SWFT_SWAP_ADDRESS[1],
                'from': "0x56f879e6586bfacafd5219207a33cae1dace7c58",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b0000000000000000000000000000000000000000000000000009f5990dc1c5000'
            },
            'block': {
                'number': 1
            },
                   
        })

        findings = agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the to is a contract"


    def test_not_transfer_from_swft_swap(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': NEW_CONTRACT,
                'from': "0x56f879e6586bfacafd5219207a33cae1dace7c58",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b0000000000000000000000000000000000000000000000000009f5990dc1c5000'
            },
            'block': {
                'number': 1
            }
        })

        findings = agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the to is not SWFT Swap"


    def test_transfer_from_swft_swap_to_new_account(self):
        agent.initialize()
        # New EOA passed in transaction.data
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': SWFT_SWAP_ADDRESS[1],
                'from': "0x56f879e6586bfacafd5219207a33cae1dace7c58",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b8000000000000000000000000000000000000000000000000009f5990dc1c5000'
            },
            'block': {
                'number': 1
            },      
        })

        findings = agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-SWFT-SWAP-NEW-ACCOUNT", "This is a tx from SWFT Swap to a new account"
        assert findings[0].severity == FindingSeverity.Medium, "Severity should be medium"


    def test_low_value_transfer_from_swft_swap(self):
        agent.initialize()
        # Low value passed in transaction.logs.data
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': SWFT_SWAP_ADDRESS[1],
                'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b9000000000000000000000000000000000000000000000000009f5990dc1c5000'

            },
            'block': {
                'number': 1
            }
        })

        findings = agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-SWFT-SWAP-LOW-AMOUNT", "This is a low value transfer from SWFT Swap"
        assert findings[0].severity == FindingSeverity.Low, "Severity should be low"

    
    def test_high_value_transfer_from_swft_swap(self):
        agent.initialize()
        # High value passed in transaction.logs.data
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': SWFT_SWAP_ADDRESS[1],
                'from': "0x077d360f11d220e4d5d831430c81c26c9be7c4a4",
                'value': "0",
                'data': '0x4782f7790000000000000000000000007a1f3a3018ebd6437248ab71a1b05e4c092cb8b9000000000000000000000000000000000000000000000000006397fa8991b2000'

            },
            'block': {
                'number': 1
            }
        })

        findings = agent.detect_swft_swap_funding(w3, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - It is to an 'old' address and is over the threshold."
