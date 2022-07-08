from unittest.mock import Mock
from forta_agent import FindingSeverity, FindingType, create_transaction_event
from agent import handle_transaction, ERC20_TRANSFER_EVENT

mock_tx_event = create_transaction_event({'transaction': {'from': '0xbeef'}})
mock_tx_event.filter_log = Mock()


class TestAnomalousTokenTransfers:
    def test_returns_empty_findings_if_no_erc20_transfers(self):
        mock_tx_event.filter_log.return_value = []

        findings = handle_transaction(mock_tx_event)

        assert len(findings) == 0
        mock_tx_event.filter_log.assert_called_once_with(ERC20_TRANSFER_EVENT)

    def test_returns_info_finding_for_normal_transfers(self):
        mock_tx_event.filter_log.reset_mock()
        from_address = mock_tx_event.from_

        amount = 1700000000
        USDT_DECIMALS = 6
        transfer_events = [{
            'args': {'value': amount * 10**USDT_DECIMALS, 'from': '0x123', 'to': '0xabc'},
            'address': '0xdac17f958d2ee523a2206206994597c13d831ec7'
        }]
        mock_tx_event.filter_log.return_value = transfer_events
        token_transfer_count =len(transfer_events)

        findings = handle_transaction(mock_tx_event)

        assert len(findings) == 1
        mock_tx_event.filter_log.assert_called_once_with(ERC20_TRANSFER_EVENT)
        finding = findings[0]
        assert finding.name == "Normal Tx with Token Transfers"
        assert finding.description == f'{from_address} executed {token_transfer_count} token transfers'
        assert finding.alert_id == "NORMAL-TOKEN-TRANSFERS-TX"
        assert finding.severity == FindingSeverity.Low
        assert finding.type == FindingType.Info

        # TODO: add prediction input, output, and score
        assert finding.metadata['from'] == from_address
        assert finding.metadata['model_input'] == []
        assert finding.metadata['model_score'] == 0.18
        assert finding.metadata['model_prediction'] == 'NORMAL'


    def test_returns_critical_finding_for_anomalous_transfers(self):
        pass
