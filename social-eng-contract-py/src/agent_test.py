from datetime import datetime

from forta_bot import create_transaction_event, EntityType
import pytest
import agent
from web3 import Web3
import rlp
from constants import CONTRACT_QUEUE_SIZE
from web3_mock import CONTRACT, EOA_ADDRESS, Web3Mock
from unittest.mock import patch

w3 = Web3Mock()

#LOWER CONTRACT_QUEUE_SIZE TO 100 FOR TESTING; run tests individually

class TestSocialEngContractAgent:
    @pytest.mark.asyncio
    async def test_contract_queue_limit(self):
        await agent.initialize()

        for i in range(CONTRACT_QUEUE_SIZE + 10):

            random_contract_address = TestSocialEngContractAgent.calc_contract_address(w3, EOA_ADDRESS, i)

            block_info = {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            }

            contract_interaction_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'to': random_contract_address,
                    'nonce': 8,
                },
                block=block_info,
                network_id=1,
            )

            await agent.detect_social_eng_account_creations(w3, contract_interaction_tx_event)

        assert(len(agent.CONTRACTS_QUEUE) == CONTRACT_QUEUE_SIZE + 1)

    def calc_contract_address(w3, address, nonce) -> str:
        """
        this function calculates the contract address from sender/nonce
        :return: contract address: str
        """

        address_bytes = bytes.fromhex(address[2:].lower())
        return Web3.to_checksum_address(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])

    @pytest.mark.asyncio
    async def test_contract_queue_handling_contract(self):
        await agent.initialize()
        contract_interaction_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'to': CONTRACT,
                    'nonce': 8,
                },
                block={
                'number': 0,
                'timestamp': datetime.now().timestamp(),
                },
                network_id=1,
            )


        await agent.detect_social_eng_account_creations(w3, contract_interaction_tx_event)
        await agent.detect_social_eng_account_creations(w3, contract_interaction_tx_event)


        assert(len(agent.CONTRACTS_QUEUE) == 2)

    @pytest.mark.asyncio
    async def test_contract_queue_handling_EOA(self):
        await agent.initialize()
        contract_interaction_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'to': EOA_ADDRESS,
                    'nonce': 8,
                },
                block={
                'number': 0,
                'timestamp': datetime.now().timestamp(),
                },
                network_id=1,
            )

        await agent.detect_social_eng_account_creations(w3, contract_interaction_tx_event)


        assert(len(agent.CONTRACTS_QUEUE) == 1)

    @pytest.mark.asyncio
    @patch("src.findings.calculate_alert_rate", return_value=1.0)
    async def test_soc_eng_contract_creation_finding(self, mocker):
        await agent.initialize()

        contract_interaction_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'to': CONTRACT,
                    'nonce': 8,
                },
                block={
                'number': 0,
                'timestamp': datetime.now().timestamp(),
                },
                network_id=1,
            )


        await agent.detect_social_eng_account_creations(w3, contract_interaction_tx_event)

        contract_creation_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'nonce': 9,
                },
                block={
                'number': 0,
                'timestamp': datetime.now().timestamp(),
                },
                network_id=1,
            )


        findings = await agent.detect_social_eng_account_creations(w3, contract_creation_tx_event)
        assert len(findings) == 1, "should have 1 finding"
        assert findings[0].alert_id == 'SOCIAL-ENG-CONTRACT-CREATION'
        assert "anomaly_score" in findings[0].metadata
        assert findings[0].labels[0].label == 'attacker', "should have attacker as label"
        assert findings[0].labels[0].entity.lower() == EOA_ADDRESS.lower(), "should have EOA address as label"
        assert findings[0].labels[0].entity_type == EntityType.Address, "should have label_type address"
        assert findings[0].labels[0].confidence == 0.6, "should have 0.3 as label confidence"

        assert findings[0].labels[1].label == 'attacker_contract', "should have attacker as label"
        assert findings[0].labels[1].entity == '0x728ad672409da288ca5b9aa85d1a55b803ba97d7', "should have contract address as label"
        assert findings[0].labels[1].entity_type == EntityType.Address, "should have label_type address"
        assert findings[0].labels[1].confidence == 0.6, "should have 0.3 as label confidence"

        assert findings[0].labels[2].label == 'victim', "should have attacker as label"
        assert findings[0].labels[2].entity == '0x728aeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee97d7', "should have contract address as label"
        assert findings[0].labels[2].entity_type == EntityType.Address, "should have label_type address"
        assert findings[0].labels[2].confidence == 0.6, "should have 0.3 as label confidence"


    @pytest.mark.asyncio
    async def test_soc_eng_contract_creation_no_finding_identical_contract(self):
        await agent.initialize()

        contract_interaction_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'to': "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7",
                    'nonce': 8,
                },
                block={
                'number': 0,
                'timestamp': datetime.now().timestamp(),
                },
                network_id=1,
            )

        await agent.detect_social_eng_account_creations(w3, contract_interaction_tx_event)

        contract_creation_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'nonce': 9,
                },
                block={
                'number': 0,
                'timestamp': datetime.now().timestamp(),
                },
                network_id=1,
            )

        findings = await agent.detect_social_eng_account_creations(w3, contract_creation_tx_event)
        assert len(findings) == 0, "should have 0 on identical contract addresses"


    @pytest.mark.asyncio
    async def test_soc_eng_contract_creation_no_finding_no_contract_in_queue(self):
        await agent.initialize()

        contract_creation_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'nonce': 9,
                },
                block={
                'number': 1,
                'timestamp': datetime.now().timestamp(),
                },
                network_id=1,
            )

        findings = await agent.detect_social_eng_account_creations(w3, contract_creation_tx_event)
        assert len(findings) == 0, "should have no finding"

    @pytest.mark.asyncio
    @patch("src.findings.calculate_alert_rate", return_value=1.0)
    async def test_soc_eng_contract_creation_finding_null_address(self, mocker):
        await agent.initialize()

        contract_creation_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': "0x425df6cf518cd4fc42f382b2f81baea0ff0b0ce7",
                    'nonce': 0,
                },
                block={
                'number': 1,
                'timestamp': datetime.now().timestamp(),
                },
                network_id=1,
            )



        findings = await agent.detect_social_eng_account_creations(w3, contract_creation_tx_event)
        assert len(findings) == 1, "should have 1 finding"
        assert "anomaly_score" in findings[0].metadata
        assert findings[0].alert_id == 'SOCIAL-ENG-CONTRACT-CREATION-NULL-ADDRESS'
        assert findings[0].labels[0].label == 'attacker', "should have attacker as label"
        assert findings[0].labels[0].entity == "0x425df6cf518cd4fc42f382b2f81baea0ff0b0ce7", "should have EOA address as label"
        assert findings[0].labels[0].entity_type == EntityType.Address, "should have label_type address"
        assert findings[0].labels[0].confidence == 0.6, "should have 0.3 as label confidence"

        assert findings[0].labels[1].label == 'attacker_contract', "should have attacker as label"
        assert findings[0].labels[1].entity == '0x00002d618fcb99cfe7af0c6505508b33fc620000', "should have contract address as label"
        assert findings[0].labels[1].confidence == 0.6, "should have 0.3 as label confidence"
        assert findings[0].labels[1].entity_type == EntityType.Address, "should have label_type address"

        assert findings[0].labels[2].label == 'victim', "should have attacker as label"
        assert findings[0].labels[2].entity == '0x0000000000000000000000000000000000000000', "should have contract address as label"
        assert findings[0].labels[2].confidence == 0.6, "should have 0.3 as label confidence"
        assert findings[0].labels[2].entity_type == EntityType.Address, "should have label_type address"


    @pytest.mark.asyncio
    @patch("src.findings.calculate_alert_rate", return_value=1.0)
    async def test_soc_eng_eoa_creation_finding_null(self, mocker):
        await agent.initialize()

        contract_creation_tx_event = create_transaction_event(
                transaction={
                    'hash': "0",
                    'from': "0x0000d672409da288ca5b9aa85d1a55b803ba0000",
                    'to': EOA_ADDRESS,
                    'value': 1000000000000000000,
                    'nonce': 9,
                },
                block={
                'number': 1,
                'timestamp': datetime.now().timestamp(),
                },
                network_id=1,
            )


        findings = await agent.detect_social_eng_account_creations(w3, contract_creation_tx_event)
        assert len(findings) == 1, "should have 1 finding"
        assert findings[0].alert_id == 'SOCIAL-ENG-EOA-CREATION-NULL-ADDRESS'
        assert "anomaly_score" in findings[0].metadata
        assert findings[0].labels[0].label == 'attacker', "should have attacker as label"
        assert findings[0].labels[0].entity == '0x0000d672409da288ca5b9aa85d1a55b803ba0000', "should have EOA address as label"
        assert findings[0].labels[0].entity_type == EntityType.Address, "should have label_type address"
        assert findings[0].labels[0].confidence == 0.6, "should have 0.3 as label confidence"

        assert findings[0].labels[1].label == 'victim', "should have attacker as label"
        assert findings[0].labels[1].entity == '0x0000000000000000000000000000000000000000', "should have contract address as label"
        assert findings[0].labels[1].confidence == 0.6, "should have 0.3 as label confidence"
        assert findings[0].labels[1].entity_type == EntityType.Address, "should have label_type address"
