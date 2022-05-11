from unittest.mock import Mock
from forta_agent import create_transaction_event
from .agent import provide_handle_transaction

mock_check_etherscan_blocklist = Mock()
mock_check_chainalysis_blocklist = Mock()
mock_check_usdc_blocklist = Mock()
mock_check_usdt_blocklist = Mock()

handle_transaction = provide_handle_transaction(mock_check_etherscan_blocklist,
                                                mock_check_usdt_blocklist,
                                                mock_check_usdc_blocklist,
                                                mock_check_chainalysis_blocklist)
mock_tx_event = create_transaction_event({})

class TestTetherTransferAgent:
    def test_returns_findings_from_large_transfer_event_agent_and_transfer_from_function_agent(self):
        mock_finding = {'some': 'finding'}
        mock_check_etherscan_blocklist.return_value = [mock_finding]
        mock_check_usdt_blocklist.return_value = [mock_finding]
        mock_check_usdc_blocklist.return_value = [mock_finding]
        mock_check_chainalysis_blocklist.return_value = [mock_finding]

        findings = handle_transaction(mock_tx_event)

        assert len(findings) == 4
        for finding in findings:
            assert finding == mock_finding

        mock_check_etherscan_blocklist.assert_called_once_with(mock_tx_event)
        mock_check_usdt_blocklist.assert_called_once_with(mock_tx_event)
        mock_check_usdc_blocklist.assert_called_once_with(mock_tx_event)
        mock_check_chainalysis_blocklist.assert_called_once_with(mock_tx_event)
