from unittest.mock import Mock
from forta_agent import create_transaction_event
from .agent import provide_handle_transaction
import src.agent

mock_check_chainalysis_oracle = Mock()

handle_transaction = provide_handle_transaction(mock_check_chainalysis_oracle)
mock_tx_event = create_transaction_event({})


class TestSanctionedAddressTxBot:
    def test_returns_findings(self):
        src.agent.initialize()

        mock_finding = {'some': 'finding'}
        mock_check_chainalysis_oracle.return_value = [mock_finding]

        findings = handle_transaction(mock_tx_event)

        assert len(findings) == 1
        for finding in findings:
            assert finding == mock_finding

        mock_check_chainalysis_oracle.assert_called_once_with(mock_tx_event)
