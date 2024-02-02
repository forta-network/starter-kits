import agent
from forta_agent import FindingSeverity, create_transaction_event, Web3, get_json_rpc_url
from src.web3_mock import Web3Mock, NEW_EOA, OLD_EOA, NEW_CONTRACT
from src.constants import FIXED_FLOAT_ADDRESS
import timeit

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

class TestFixedFloatFundingAgent:
    def test_transfer_to_contract(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': NEW_CONTRACT,
                'from': FIXED_FLOAT_ADDRESS[1],
                'value': "1000000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_fixed_float_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the to is a contract"


    def test_not_transfer_from_fixed_float(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': NEW_EOA,
                'from': OLD_EOA,
                'value': "1000000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_fixed_float_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the from is not Fixed Float"


    def test_transfer_from_fixed_float_to_new_account(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': NEW_EOA,
                'from': FIXED_FLOAT_ADDRESS[1],
                'value': "100000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_fixed_float_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-FIXED-FLOAT-NEW-ACCOUNT", "This is a tx from Fixed Float to a new account"
        assert findings[0].severity == FindingSeverity.Medium, "Severity should be medium"


    def test_low_value_transfer_from_fixed_float(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': OLD_EOA,
                'from': FIXED_FLOAT_ADDRESS[1],
                'value': "3000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_fixed_float_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-FIXED-FLOAT-LOW-AMOUNT", "This is a low value transfer from Fixed Float"
        assert findings[0].severity == FindingSeverity.Low, "Severity should be low"

    
    def test_high_value_transfer_from_fixed_float(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': OLD_EOA,
                'from': FIXED_FLOAT_ADDRESS[1],
                'value': "300000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_fixed_float_funding(w3, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - It is to an address that has sent a transaction and is over the threshold."
