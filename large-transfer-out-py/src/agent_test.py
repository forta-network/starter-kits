from forta_agent import create_transaction_event, FindingSeverity
import agent
from web3_mock import Web3Mock, ADDRESS_WITH_LARGE_BALANCE, ADDRESS_WITHOUT_LARGE_BALANCE, CURRENT_BLOCK, OLDER_CURRENT_BLOCK

w3 = Web3Mock()


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

    