from unittest.mock import patch
from forta_bot import create_transaction_event, EntityType
import pytest
import agent
from web3_mock import Web3Mock, NEW_EOA, OLD_EOA, NEW_CONTRACT

w3 = Web3Mock()


class TestDEXFunding:
    @pytest.mark.asyncio
    async def test_not_transfer_to_cex(self):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                "hash": "0",
                "to": NEW_EOA,
                "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e0000",
                "value": "1000000000000000000",
            },
            block = {
                'number': 1
            },
            network_id = 1
        )

        findings = await agent.detect_cex_funding(w3, tx_event)
        assert (
            len(findings) == 0
        ), "this should have not triggered a finding as the from is not a CEX"

    @pytest.mark.asyncio
    async def test_transfer_to_contract(self):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                "hash": "0",
                "to": NEW_CONTRACT,
                "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e0000",
                "value": "1000000000000000000",
            },
            block = {
                'number': 1
            },
            network_id = 1
        )

        findings = await agent.detect_cex_funding(w3, tx_event)
        assert (
            len(findings) == 0
        ), "this should have not triggered a finding is to a contract"

    @pytest.mark.asyncio
    async def test_transfer_to_old_eoa(self):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                "hash": "0",
                "to": OLD_EOA,
                "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e0000",
                "value": "1000000000000000000",
            },
            block = {
                'number': 1
            },
            network_id = 1
        )

        findings = await agent.detect_cex_funding(w3, tx_event)
        assert (
            len(findings) == 0
        ), "this should have not triggered a finding is to an old EOA"

    @pytest.mark.asyncio
    async def test_transfer_excessive_amount(self):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                "hash": "0",
                "to": NEW_EOA,
                "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e0000",
                "value": "3000000000000000000",
            },
            block = {
                'number': 1
            },
            network_id = 1
        )

        findings = await agent.detect_cex_funding(w3, tx_event)
        assert (
            len(findings) == 0
        ), "this should have not triggered a finding as funding amount is too large"

    @pytest.mark.asyncio
    @patch("findings.calculate_alert_rate", return_value=1.0)
    @patch('agent.get_chain_id', return_value=1)
    async def test_cex_funding(self, mock_calculate_alert_rate, mock_get_chain_id):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction = {
                "hash": "0",
                "to": NEW_EOA,
                "from": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f",
                "value": "1000000000000000000",
            },
            block = {
                'number': 1
            },
            network_id = 1
        )

        findings = await agent.detect_cex_funding(w3, tx_event)
        print(f"findings[0].labels[0]: {findings[0].labels[0]}")
        assert len(findings) == 1, "this should have triggered a finding"

        assert (
            findings[0].metadata["anomaly_score"] == str(1.0)
        ), "should have anomaly score of 1.0"
        assert (
            findings[0].labels[0].entity == NEW_EOA.lower()
        ), "should have EOA address as label"
        assert (
            findings[0].labels[0].entity_type == EntityType.Address
        ), "should have label_type address"
        assert (
            findings[0].labels[0].label == "attacker"
        ), "should have attacker as label"
