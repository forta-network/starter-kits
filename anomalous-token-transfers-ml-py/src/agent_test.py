from unittest.mock import Mock, patch
from forta_agent import FindingSeverity, FindingType, create_transaction_event
import agent

mock_tx_event = create_transaction_event({'transaction': {'from': '0xbeef'}, 'block': {'timestamp': 1655403557}})
mock_tx_event.filter_log = Mock()


# INITIALIZE MODEL
class TestAnomalousTokenTransfers:
    def test_returns_empty_findings_if_no_erc20_transfers(self):
        mock_tx_event.filter_log.return_value = []

        findings = agent.handle_transaction(mock_tx_event)

        assert len(findings) == 0
        mock_tx_event.filter_log.assert_called_once_with(agent.ERC20_TRANSFER_EVENT)

    @patch('agent.get_first_tx_timestamp')
    @patch('agent.get_token_info')
    def test_returns_info_finding_for_normal_transfers(self, mock_get_token_info, mock_get_first_tx_timestamp):
        agent.initialize()
        mock_tx_event.filter_log.reset_mock()
        from_address = mock_tx_event.from_

        amount = 1700000000
        USDT_TOKEN_ADDR = '0xdac17f958d2ee523a2206206994597c13d831ec7'
        transfer_events = [{
            'args': {'value': amount, 'from': '0x123', 'to': '0xabc'},
            'address': USDT_TOKEN_ADDR
        }]
        mock_tx_event.filter_log.return_value = transfer_events
        token_transfer_count =len(transfer_events)

        mock_get_first_tx_timestamp.return_value = 1655403557
        mock_get_token_info.return_value = ('Tether USD', 'USDT', 6)

        findings = agent.handle_transaction(mock_tx_event)

        assert len(findings) == 1
        mock_get_first_tx_timestamp.assert_called_once_with('0xbeef')
        mock_get_token_info.assert_called_once_with(USDT_TOKEN_ADDR)
        mock_tx_event.filter_log.assert_called_once_with(agent.ERC20_TRANSFER_EVENT)
        finding = findings[0]
        assert finding.name == "Normal Tx with Token Transfers"
        assert finding.description == f'{from_address} executed {token_transfer_count} token transfers'
        assert finding.alert_id == "NORMAL-TOKEN-TRANSFERS-TX"
        assert finding.severity == FindingSeverity.Low
        assert finding.type == FindingType.Info

        assert finding.metadata['from'] == from_address
        assert finding.metadata['model_input'] == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1700,0,0,0,0,0,1,1700,1,1]
        assert finding.metadata['token_types'] == ["Tether USD-USDT"]
        assert finding.metadata['max_single_token_transfers_name'] == "Tether USD"
        assert finding.metadata['model_score'] == 0.189
        assert finding.metadata['model_prediction'] == 'NORMAL'


    def test_returns_critical_finding_for_anomalous_transfers(self):
        pass
