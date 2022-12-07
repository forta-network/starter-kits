from forta_agent import FindingSeverity, create_transaction_event
from web3_mock import Web3Mock
import agent

from constants import VICTIM_NOTIFIER_LIST

EOA_ADDRESS_1 = "0x000000000000000000000000000000000000000A"
EOA_ADDRESS_2 = "0x000000000000000000000000000000000000000B"

w3 = Web3Mock()


class TestVictimNotifications:

    def test_victim_notification_pos(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': VICTIM_NOTIFIER_LIST[0],
                'value': 0,
                'to': EOA_ADDRESS_1,
                'data': '0x4865790d0a0d0a596f75206861766520617070726f76656420612066616b6520636f6e74726163742c206974e280997320746f6f6b20796f757220657263323020746f6b656e732020616e64206e667473200d0a0d0a506c65617365207265766f6b652074686520636f6e747261637420616e64207265616368207573206261636b2077652063616e207265636f766572207468652066756e6473207573696e6720636f6e74726163742066756e6374696f6e200d0a436865636b206368617420696e20626c6f636b7363616e206f6e20796f75722061646472657373200d0a0d0a4f72206d61696c203a20746f726e61646f63617368406d61696c2e696f0d0a0d0a4f72206a6f696e2063686174203a2068747470733a2f2f636861742e626c6f636b7363616e2e636f6d'
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_victim_notification(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "VICTIM-NOTIFICATION-1"
        assert findings[0].severity == FindingSeverity.Info

    def test_victim_notification_not_in_notifier_list(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS_2,
                'value': 0,
                'to': EOA_ADDRESS_1,
                'data': '0x4865790d0a0d0a596f75206861766520617070726f76656420612066616b6520636f6e74726163742c206974e280997320746f6f6b20796f757220657263323020746f6b656e732020616e64206e667473200d0a0d0a506c65617365207265766f6b652074686520636f6e747261637420616e64207265616368207573206261636b2077652063616e207265636f766572207468652066756e6473207573696e6720636f6e74726163742066756e6374696f6e200d0a436865636b206368617420696e20626c6f636b7363616e206f6e20796f75722061646472657373200d0a0d0a4f72206d61696c203a20746f726e61646f63617368406d61696c2e696f0d0a0d0a4f72206a6f696e2063686174203a2068747470733a2f2f636861742e626c6f636b7363616e2e636f6d'
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_victim_notification(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding"

    def test_victim_notification_no_input(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': VICTIM_NOTIFIER_LIST[0],
                'value': 0,
                'to': EOA_ADDRESS_1,
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_victim_notification(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"
