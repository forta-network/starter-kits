from unittest.mock import MagicMock
import agent
from forta_bot_sdk import create_transaction_event, TransactionEvent, get_chain_id
from web3_mock import *
from rules import AddressPoisoningRules
from blockexplorer_mock import BlockExplorerMock
from blockexplorer import BlockExplorer
import timeit
import pytest
from unittest.mock import patch
from web3 import AsyncWeb3


w3 = Web3Mock()
blockexplorer = BlockExplorerMock(w3.eth.chain_id)
heuristic = AddressPoisoningRules()

w3.to_checksum_address = AsyncWeb3.to_checksum_address
real_w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider("https://rpc.ankr.com/eth"))


@pytest.fixture(scope="module")
async def real_blockexplorer():
    yield BlockExplorer(get_chain_id())


class TestAddressPoisoningAgent:

    @pytest.mark.asyncio
    async def test_transaction_processing_speed(self, real_blockexplorer):
        agent.CHAIN_ID = 1

        global transaction_to_eoa
        transaction_to_eoa = create_transaction_event(
            {
                'hash': "0x4a419b16152cc6513db84bdfb94818827ef8e64c2bc52f9a95f960c47ef02817",
                'from': "0x5b7d833a4aa182bddd754db797d43d3c29c171a0",
                'value': 100,
                'to': "0xb2880739e3bd3f535d38760cd8f2ee058737341b",
            },
            {},
            1
        )

        global transaction_to_contract
        transaction_to_contract = create_transaction_event(
            {
                'hash': "0x00159936a7412553e0736c6f4d6cf91028ddd2defb8a3427318f7599b941f42d",
                'from': "0xb2880739e3bd3f535d38760cd8f2ee058737341b",
                'value': 0,
                'to': "0xa9d7c7466b9d0a76397d5a226da0024fdcff0ee1",
            },
            {},
            1
        )

        global transaction_to_verified_contract
        transaction_to_verified_contract = create_transaction_event(
            {
                'hash': "0x0af2f2d106bff1950805d610e927344a2477b8be138ab4d4269e72b9aab5ddec",
                'from': "0x2a038e100f8b85df21e4d44121bdbfe0c288a869",
                'value': 0,
                'to': "0xba8da9dcf11b50b03fd5284f164ef5cdef910705",
            },
            {},
            1
        )

        global fake_token_phishing_tx
        fake_token_phishing_tx = create_transaction_event(
            {
                'hash': "0xae818f01e8e911da67d87a577ecfc04443cad96ac3e099b2dac44633594d7311",
                'from': "0xb2880739e3bd3f535d38760cd8f2ee058737341b",
                'value': 0,
                'to': "0xa9d7c7466b9d0a76397d5a226da0024fdcff0ee1",
            },
            {},
            1
        )

        # Chain: Blocktime, Number of Tx -> Avg processing time in ms target
        # Ethereum: 12s, 150 -> 80ms
        # BSC: 3s, 70 -> 43ms
        # Polygon: 2s, 50 -> 40ms
        # Avalanche: 2s, 5 -> 400ms
        # Arbitrum: 1s, 5 -> 200ms
        # Optimism: 24s, 150 -> 160ms
        # Fantom: 1s, 5 -> 200ms

        processing_runs = 10

        processing_time_to_eoa = 0
        for _ in range(processing_runs):
            start_time = asyncio.get_event_loop().time()
            await agent.detect_address_poisoning(real_w3, real_blockexplorer, heuristic, transaction_to_eoa)
            end_time = asyncio.get_event_loop().time()
            processing_time_to_eoa += (end_time - start_time) * 1000
        processing_time_to_eoa /= processing_runs

        processing_time_to_contract = 0
        for _ in range(processing_runs):
            start_time = asyncio.get_event_loop().time()
            await agent.detect_address_poisoning(real_w3, real_blockexplorer, heuristic, transaction_to_contract)
            end_time = asyncio.get_event_loop().time()
            processing_time_to_contract += (end_time - start_time) * 1000
        processing_time_to_contract /= processing_runs

        processing_time_to_verified_contract = 0
        for _ in range(processing_runs):
            start_time = asyncio.get_event_loop().time()
            await agent.detect_address_poisoning(real_w3, real_blockexplorer, heuristic, transaction_to_verified_contract)
            end_time = asyncio.get_event_loop().time()
            processing_time_to_verified_contract += (end_time - start_time) * 1000
        processing_time_to_verified_contract /= processing_runs

        processing_time_fake_token = 0
        for _ in range(processing_runs):
            start_time = asyncio.get_event_loop().time()
            await agent.detect_address_poisoning(real_w3, real_blockexplorer, heuristic, fake_token_phishing_tx)
            end_time = asyncio.get_event_loop().time()
            processing_time_fake_token += (end_time - start_time) * 1000
        processing_time_fake_token /= processing_runs

        assert (processing_time_to_eoa * 0.33 + processing_time_to_contract * 0.33 + processing_time_to_verified_contract * 0.33 + processing_time_fake_token * 0.01) / 8 < 160, f"Time is {(processing_time_to_eoa * 0.33 + processing_time_to_contract * 0.33 + processing_time_to_verified_contract * 0.33 + processing_time_fake_token * 0.01) / 8}, normal: {processing_time_to_eoa}  - {processing_time_to_contract}  - {processing_time_to_verified_contract}  - {processing_time_fake_token} "

    @pytest.mark.asyncio
    async def test_transfer_to_eoa(self):
        tx_event = create_transaction_event({
            'to': NEW_EOA,
            'from': OLD_EOA,
            'hash': "0xpositive_zero"
        },
            {},
            1
        )

        findings = await agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - not to a contract"

    @pytest.mark.asyncio
    async def test_get_attacker_victim_lists_for_zero_value(self):
        alert_type = "ZERO-VALUE-ADDRESS-POISONING"
        logs = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "0"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "0"
                }
            }
        ]

        attackers, victims = await agent.get_attacker_victim_lists(w3, logs, alert_type)
        assert len([a for a in attackers if "attacker" in a]) == len(attackers)
        assert len([v for v in victims if v == "victim"]) == len(victims)

    @pytest.mark.asyncio
    async def test_get_attacker_victim_lists_for_low_value(self):
        alert_type = "ADDRESS-POISONING-LOW-VALUE"
        logs = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "attacker_contract",
                    "value": "82300"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "victim",
                    "from": "attacker",
                    "value": "82300"
                }
            }
        ]

        attackers, victims = await agent.get_attacker_victim_lists(w3, logs, alert_type)
        assert len([a for a in attackers if "attacker" in a]) == len(attackers)
        assert len([v for v in victims if v == "victim"]) == len(victims)
        assert len(attackers) - len(victims) == 1

    def test_positive_check_for_similar_transfer(self):
        victims = ["victim"]
        logs = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "attacker_contract",
                    "value": "82300"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "victim",
                    "from": "attacker",
                    "value": "82300"
                }
            }
        ]

        check_result = agent.check_for_similar_transfer(blockexplorer, logs, victims)
        assert check_result, "This should find a matching value"

        def test_negative_check_for_similar_transfer(self):
            victims = ["user_one"]
            logs = [
                {
                    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "args": {
                        "to": "user_one",
                        "from": "user_two",
                        "value": "82300"
                    }
                },
                {
                    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "args": {
                        "to": "user_three",
                        "from": "user_four",
                        "value": "82300"
                    }
                }
            ]

            check_result = agent.check_for_similar_transfer(blockexplorer, logs, victims)
            assert not check_result, "This should not find a matching value"

    @pytest.mark.asyncio
    async def test_is_zero_value_address_poisoning(self):
        await agent.initialize()
        agent.CHAIN_ID = 1

        tx_event = TransactionEvent({
            'transaction': {
                'hash': "0xpositive_zero",
                'from': NEW_EOA,
                'to': CONTRACT
            },
            'logs': [
                {
                    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "args": {
                        "to": "attacker",
                        "from": "victim",
                        "value": "0"
                    }
                },
                {
                    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "args": {
                        "to": "attacker",
                        "from": "victim",
                        "value": "0"}
                }
            ]
        })

        findings = await agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 1, "This should have triggered an alert - positive case"
        assert findings[0].alert_id == "ADDRESS-POISONING-ZERO-VALUE"

    @pytest.mark.asyncio
    async def test_is_not_zero_value_address_poisoning(self):
        await agent.initialize()
        agent.CHAIN_ID = 1

        tx_event = TransactionEvent({
            'transaction': {
                'hash': "0xnegative_zero",
                'from': NEW_EOA,
                'to': CONTRACT
            },
            'logs': [
                {
                    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "args": {
                        "to": "attacker",
                        "from": "victim",
                        "value": "0"
                    }
                },
                {
                    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "args": {
                        "to": "attacker",
                        "from": "victim",
                        "value": "0"
                    }
                }
            ]
        })

        findings = await agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered an alert - negative case"

    @pytest.mark.asyncio
    async def test_is_low_value_address_poisoning(self):
        await agent.initialize()
        agent.CHAIN_ID = 1

        tx_event = MagicMock(spec=TransactionEvent)
        tx_event.hash = "0xpositive_low"
        tx_event.from_ = NEW_EOA
        tx_event.to = CONTRACT
        tx_event.filter_log.return_value = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "attacker_contract",
                    "value": "82300"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "victim",
                    "from": "attacker",
                    "value": "82300"
                }
            }
        ]

        findings = await agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 1
        assert findings[0].alert_id == "ADDRESS-POISONING-LOW-VALUE"

    @pytest.mark.asyncio
    async def test_is_not_low_value_address_poisoning(self):
        await agent.initialize()
        agent.CHAIN_ID = 1

        tx_event = TransactionEvent({
            'transaction': {
                'hash': "0xnegative_low",
                'from': NEW_EOA,
                'to': CONTRACT
            },
            'logs': [
                {
                    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "args": {
                        "to": "user_one",
                        "from": "user_two",
                        "value": "1600"
                    }
                },
                {
                    "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "args": {
                        "to": "user_three",
                        "from": "user_four",
                        "value": "15000"
                    }
                }
            ]
        })

        findings = await agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered an alert - negative case"

    @pytest.mark.asyncio
    async def test_is_fake_token_address_poisoning(self):
        agent.CHAIN_ID = 1

        tx_event = TransactionEvent({
            'transaction': {
                'hash': "0xpositive_fake_token",
                'from': NEW_EOA,
                'to': CONTRACT
            },
            'logs': [
                {
                    "address": "0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F",
                    "args": {
                        "to": "attacker",
                        "from": "victim",
                        "value": "3000"
                    }
                },
                {
                    "address": "0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F",
                    "args": {
                        "to": "attacker",
                        "from": "victim",
                        "value": "4000"
                    }
                }
            ]
        })

        findings = await agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 1, "This should have triggered an alert - positive case"

    @pytest.mark.asyncio
    async def test_is_not_fake_token_address_poisoning(self):
        await agent.initialize()
        agent.CHAIN_ID = 1

        tx_event = MagicMock(spec=TransactionEvent)
        tx_event.transaction = {}
        tx_event.to = CONTRACT
        tx_event.from_ = NEW_EOA
        tx_event.hash = "0xnegative_fake_token"
        tx_event.filter_log.return_value = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "3000"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "4000"
                }
            }
        ]

        findings = await agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered an alert - negative case"

    @pytest.mark.asyncio
    async def test_is_null_address_in_logs(self):
        await agent.initialize()

        tx_event = MagicMock(spec=TransactionEvent)
        tx_event.transaction = {}
        tx_event.to = CONTRACT
        tx_event.from_ = NEW_EOA
        tx_event.hash = "0x_token_mint"

        findings = await agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 0, "This is a minting transaction, so should not have triggered."
