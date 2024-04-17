import agent
from forta_agent import FindingSeverity, create_transaction_event, Web3, get_json_rpc_url
from src.web3_mock import Web3Mock, NEW_EOA, OLD_EOA, NEW_CONTRACT
from src.constants import EXCH_ADDRESS

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

class TestExchFundingBot:
    
    def test_transfer_to_contract(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': NEW_CONTRACT,
                'from': EXCH_ADDRESS,
                'value': "1000000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_exch_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the to is a contract"


    def test_not_transfer_from_exch(self):
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

        findings = agent.detect_exch_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the from is not eXch"


    def test_transfer_from_exch_to_new_account(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': NEW_EOA,
                'from': EXCH_ADDRESS,
                'value': "100000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_exch_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-EXCH-NEW-ACCOUNT", "This is a tx from eXch to a new account"
        assert findings[0].severity == FindingSeverity.Medium, "Severity should be medium"


    def test_low_value_transfer_from_exch(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': OLD_EOA,
                'from': EXCH_ADDRESS,
                'value': "3000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_exch_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-EXCH-LOW-AMOUNT", "This is a low value transfer from eXch"
        assert findings[0].severity == FindingSeverity.Low, "Severity should be low"

    
    def test_high_value_transfer_from_exch(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': OLD_EOA,
                'from': EXCH_ADDRESS,
                'value': "300000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_exch_funding(w3, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - It is to an address that has sent a transaction and is over the threshold."
