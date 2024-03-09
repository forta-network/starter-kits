from forta_bot import FindingSeverity, create_transaction_event
from web3_mock import Web3Mock
from unittest.mock import patch
import agent
import pytest

EOA_ADDRESS = "0x0000000000000000000000000000000000000001"
KNOWN_MALICIOUS_ACCOUNT = "0x000000000532b45f47779fce440748893b257865"

w3 = Web3Mock()


class TestKnownMaliciousAccountFunding:
    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_funding(self, mocker):
        await agent.initialize()

        tx_event = create_transaction_event (
            transaction= {
                "hash": "0",
                "from": KNOWN_MALICIOUS_ACCOUNT,
                "value": 10,
                "to": EOA_ADDRESS,
            },
            block={
                'number': 0
            },
            chain_id=1,
            logs= []
        )

        findings = await agent.detect_funding(tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "MALICIOUS-ACCOUNT-FUNDING"
        assert findings[0].severity == FindingSeverity.High

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_funding_novalue(self, mocker):
        await agent.initialize()

        tx_event = create_transaction_event (
            transaction= {
                "hash": "0",
                "from": KNOWN_MALICIOUS_ACCOUNT,
                "value": 0,
                "to": EOA_ADDRESS,
            },
            block={
                'number': 0
            },
            chain_id=1,
            logs= []
        )

        findings = await agent.detect_funding(tx_event)
        assert (
            len(findings) == 0
        ), "this should have not triggered a finding as no funds were transferred"
