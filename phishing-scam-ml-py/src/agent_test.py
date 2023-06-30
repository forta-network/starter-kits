from forta_agent import create_transaction_event
import agent

mock_tx_event = create_transaction_event(
    {
        "transaction": {"hash": "0x123", "from": "0xbeef", "value": 0},
        "block": {"timestamp": 1655403557},
    }
)


class TestAnomalousTokenTransfers:
    def test_returns_empty_findings_if_zero_eth_transfers(self):
        findings = agent.handle_transaction(mock_tx_event)

        assert len(findings) == 0
