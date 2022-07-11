from unittest.mock import Mock, patch
from forta_agent import FindingSeverity, FindingType, create_transaction_event
import agent
import data_processing

mock_tx_event = create_transaction_event({'transaction': {'from': '0xbeef'}, 'block': {'timestamp': 1655403557}})
mock_tx_event.filter_log = Mock()

USDT_TOKEN_ADDR = '0xdac17f958d2ee523a2206206994597c13d831ec7'
USDT_TRANSFER = {
    'args': {'value': 1700000000, 'from': '0x123', 'to': '0xabc'},
    'address': USDT_TOKEN_ADDR
}
USDC_TOKEN_ADDR = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
USDC_TRANSFER = {
    'args': {'value': 5000000000, 'from': '0x123', 'to': '0xabc'},
    'address': USDC_TOKEN_ADDR
}


class TestAnomalousTokenTransfers:
    def test_returns_empty_findings_if_no_erc20_transfers(self):
        mock_tx_event.filter_log.return_value = []

        findings = agent.handle_transaction(mock_tx_event)

        assert len(findings) == 0
        mock_tx_event.filter_log.assert_called_once_with(agent.ERC20_TRANSFER_EVENT)

    @patch('data_processing.get_first_tx_timestamp')
    @patch('data_processing.get_token_info')
    def test_returns_finding_for_normal_transfers(self, mock_get_token_info, mock_get_first_tx_timestamp):
        agent.initialize()
        mock_tx_event.filter_log.reset_mock()
        from_address = mock_tx_event.from_

        mock_tx_event.filter_log.return_value = [USDT_TRANSFER]

        mock_get_first_tx_timestamp.return_value = 1655403557
        mock_get_token_info.return_value = ('Tether USD', 'USDT', 6)

        findings = agent.handle_transaction(mock_tx_event)

        assert len(findings) == 1
        mock_get_first_tx_timestamp.assert_called_once_with('0xbeef')
        mock_get_token_info.assert_called_once_with(USDT_TOKEN_ADDR)
        mock_tx_event.filter_log.assert_called_once_with(agent.ERC20_TRANSFER_EVENT)
        finding = findings[0]
        assert finding.name == "Normal Transaction"
        assert finding.description == f'{from_address} executed normal tx with token transfers'
        assert finding.alert_id == "NORMAL-TOKEN-TRANSFERS-TX"
        assert finding.severity == FindingSeverity.Info
        assert finding.type == FindingType.Info

        assert finding.metadata['from'] == from_address
        assert finding.metadata['account_age_in_minutes'] == 0
        assert finding.metadata['USDT_transfers'] == 1
        assert finding.metadata['USDT_value'] == 1700
        assert finding.metadata['token_types'] == ["Tether USD-USDT"]
        assert finding.metadata['max_single_token_transfers_name'] == "Tether USD"
        assert finding.metadata['model_score'] == 0.189
        assert finding.metadata['model_prediction'] == 'NORMAL'

    @patch('data_processing.get_first_tx_timestamp')
    @patch('data_processing.get_token_info')
    def test_returns_findings_if_invalid_model_features(self, mock_get_token_info, mock_get_first_tx_timestamp):
        mock_tx_event.filter_log.reset_mock()
        mock_tx_event.filter_log.return_value = [USDT_TRANSFER]
        from_address = mock_tx_event.from_

        mock_get_first_tx_timestamp.return_value = -1 # invalid first tx timestamp value
        mock_get_token_info.return_value = ('Tether USD', 'USDT', 6)
        findings = agent.handle_transaction(mock_tx_event)

        assert len(findings) == 1

        finding = findings[0]
        assert finding.name == "Invalid Model Features"
        assert finding.description == f'Model input generation failed for tx executed by {from_address}'
        assert finding.alert_id == "INVALID-TOKEN-TRANSFERS-TX"
        assert finding.severity == FindingSeverity.Low
        assert finding.type == FindingType.Info

    @patch('data_processing.get_first_tx_timestamp')
    @patch('data_processing.get_token_info')
    def test_returns_finding_for_anomalous_transfers(self, mock_get_token_info, mock_get_first_tx_timestamp):
        mock_tx_event.filter_log.reset_mock()
        mock_tx_event.filter_log.return_value = [USDT_TRANSFER] * 1_000 + [USDC_TRANSFER] * 1_000
        from_address = mock_tx_event.from_

        mock_get_first_tx_timestamp.return_value = 1655403557
        mock_get_token_info.side_effect = [('Tether USD', 'USDT', 6)] * 1_000 + [('USD Coin', 'USDC', 6)] * 1_000
        findings = agent.handle_transaction(mock_tx_event)

        assert len(findings) == 1

        finding = findings[0]
        assert finding.name == "Anomalous Transaction"
        assert finding.description == f'{from_address} executed anomalous tx with token transfers'
        assert finding.alert_id == "ANOMALOUS-TOKEN-TRANSFERS-TX"
        assert finding.severity == FindingSeverity.Critical
        assert finding.type == FindingType.Suspicious

        assert finding.metadata['token_types'] == ['Tether USD-USDT', 'USD Coin-USDC']
        assert finding.metadata['model_score'] == -0.068
        assert finding.metadata['model_prediction'] == 'ANOMALY'
