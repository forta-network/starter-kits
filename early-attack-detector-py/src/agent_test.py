from forta_bot_sdk import FindingSeverity, create_transaction_event
import threading
import time
import agent
import utils
import pytest
from evmdasm import EvmBytecode
from web3 import AsyncWeb3
from unittest.mock import patch, AsyncMock
from web3_mock import (
    CONTRACT_NO_ADDRESS,
    CONTRACT_WITH_ADDRESS,
    EOA_ADDRESS,
    MALICIOUS_CONTRACT,
    MALICIOUS_CONTRACT_DEPLOYER,
    MALICIOUS_CONTRACT_DEPLOYER_NONCE,
    Web3Mock,
)

w3 = Web3Mock()
w3.to_checksum_address = AsyncWeb3.to_checksum_address
w3.keccak = AsyncWeb3.keccak

class TestEarlyAttackDetector:
    # @pytest.mark.asyncio
    # async def test_is_contract_eoa(self):
    #     assert not await utils.is_contract(
    #         w3, EOA_ADDRESS
    #     ), "EOA shouldn't be identified as a contract"

    # @pytest.mark.asyncio
    # async def test_is_contract_contract(self):
    #     assert await utils.is_contract(
    #         w3, CONTRACT_NO_ADDRESS
    #     ), "Contract should be identified as a contract"

    # @pytest.mark.asyncio
    # async def test_opcode_addresses_no_addr(self):
    #     bytecode = await w3.eth.get_code(CONTRACT_NO_ADDRESS)
    #     opcodes = EvmBytecode(bytecode.hex()).disassemble()
    #     _, addresses = await agent.get_features(w3, opcodes, EOA_ADDRESS)
    #     assert len(addresses) == 0, "should be empty"

    # @pytest.mark.asyncio
    # async def test_opcode_addresses_with_addr(self):
    #     bytecode = await w3.eth.get_code(CONTRACT_WITH_ADDRESS)
    #     opcodes = EvmBytecode(bytecode.hex()).disassemble()
    #     _, addresses = await agent.get_features(w3, opcodes, EOA_ADDRESS)

    #     assert len(addresses) == 1, "should not be empty"

    # @pytest.mark.asyncio
    # async def test_storage_addresses_with_addr(self):
    #     addresses = await agent.get_storage_addresses(w3, CONTRACT_WITH_ADDRESS)
    #     assert len(addresses) == 1, "should not be empty"

    # @pytest.mark.asyncio
    # async def test_storage_addresses_on_eoa(self):
    #     addresses = await agent.get_storage_addresses(w3, EOA_ADDRESS)
    #     assert len(addresses) == 0, "should be empty; EOA has no storage"

    # @pytest.mark.asyncio
    # async def test_calc_contract_address(self):
    #     contract_address = agent.calc_contract_address(w3, EOA_ADDRESS, 9)
    #     assert (
    #         contract_address == "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7"
    #     ), "should be the same contract address"

    # @pytest.mark.asyncio
    # async def test_get_function_signatures(self):
    #     bytecode = await w3.eth.get_code(MALICIOUS_CONTRACT)
    #     opcodes = EvmBytecode(bytecode.hex()).disassemble()
    #     function_signatures = agent.get_function_signatures(w3, opcodes)
    #     assert(len(function_signatures)==8)
    #     assert("0x1e9a6950" in function_signatures)

    # @pytest.mark.asyncio
    # async def test_get_features(self):
    #     bytecode = await w3.eth.get_code(MALICIOUS_CONTRACT)
    #     opcodes = EvmBytecode(bytecode.hex()).disassemble()
    #     features, _ = await agent.get_features(w3, opcodes, EOA_ADDRESS)
    #     assert len(features) == 4572, "incorrect features length obtained"

    # @pytest.mark.asyncio
    # async def test_get_features(self):
    #     bytecode = await w3.eth.get_code(MALICIOUS_CONTRACT)
    #     opcodes = EvmBytecode(bytecode.hex()).disassemble()
    #     features, _ = await agent.get_features(w3, opcodes, EOA_ADDRESS)
    #     assert len(features) == 4572, "incorrect features length obtained"

    # # Test for Concurrency and Performance
    # @pytest.mark.asyncio
    # async def test_concurrent_access_to_get_storage_addresses(self):
    #     number_of_threads = 10  # Number of threads to simulate concurrency
    #     threads = []
    #     results = [None] * number_of_threads  # to store results
    #     execution_times = [0] * number_of_threads  # to store execution times

    #     # Worker thread function
    #     @pytest.mark.asyncio
    #     async def thread_function(index):
    #         start_time = time.time()
    #         result = await agent.get_storage_addresses(w3, CONTRACT_WITH_ADDRESS)
    #         end_time = time.time()

    #         results[index] = result
    #         execution_times[index] = end_time - start_time

    #     # Start threads
    #     for i in range(number_of_threads):
    #         thread = threading.Thread(target=thread_function, args=(i,))
    #         threads.append(thread)
    #         thread.start()

    #     # Wait for all threads to complete
    #     for thread in threads:
    #         thread.join()

    #     # Check results and print performance data
    #     for i in range(number_of_threads):
    #         print(f'Thread {i}: Execution time {execution_times[i]:.4f} seconds')
    #         assert isinstance(results[i], set), "Expected result type is set"

    # # Test for Concurrency and Performance
    # @pytest.mark.asyncio
    # async def test_concurrent_access_to_get_storage_addresses_with_none_contract_address(self):
    #     number_of_threads = 10
    #     threads = []
    #     results = [None] * number_of_threads
    #     execution_times = [0] * number_of_threads

    #     @pytest.mark.asyncio
    #     async def thread_function(index):
    #         start_time = time.time()
    #         result = await agent.get_storage_addresses(w3, EOA_ADDRESS)
    #         end_time = time.time()

    #         results[index] = result
    #         execution_times[index] = end_time - start_time

    #     for i in range(number_of_threads):
    #         thread = threading.Thread(target=thread_function, args=(i,))
    #         threads.append(thread)
    #         thread.start()

    #     for thread in threads:
    #         thread.join()

    #     # Check if function returns an empty set
    #     for i in range(number_of_threads):
    #         print(f'Thread {i}: Execution time {execution_times[i]:.4f} seconds')
    #         assert results[i] == set(), "Function should return an empty set for None address"

    # @pytest.mark.asyncio
    # async def test_concurrent_access_to_get_storage_addresses_with_invalid_address(self):
    #     number_of_threads = 10
    #     threads = []
    #     results = [None] * number_of_threads
    #     execution_times = [0] * number_of_threads
    #     exceptions = [None] * number_of_threads  # Array to store exceptions

    #     @pytest.mark.asyncio
    #     async def thread_function(index):
    #         try:
    #             start_time = time.time()
    #             result = await agent.get_storage_addresses(w3, "12345")
    #             end_time = time.time()
    #             results[index] = result
    #             execution_times[index] = end_time - start_time
    #         except ValueError as e:
    #             exceptions[index] = e  # Store the exception

    #     for i in range(number_of_threads):
    #         thread = threading.Thread(target=thread_function, args=(i,))
    #         threads.append(thread)
    #         thread.start()

    #     for thread in threads:
    #         thread.join()

    #     # Check for exceptions in each thread
    #     for i, exception in enumerate(exceptions):
    #         assert isinstance(exception, ValueError), f"Thread {i} did not raise ValueError as expected"

    # @pytest.mark.asyncio
    # @patch('utils.aiohttp.ClientSession', autospec=True)
    # async def test_alert_count_success(self, mock_session):
    #   # Setup the mock for the async context manager correctly
    #   mock_session.return_value.__aenter__.return_value = mock_session.return_value
    #   mock_session.return_value.__aexit__.return_value = AsyncMock()

    #   mock_response = AsyncMock()
    #   mock_response.json = AsyncMock(return_value={
    #       "alertIds": {"alert1": {"count": 10}},
    #       "total": {"count": 50}
    #   })

    #   mock_session.return_value.get.return_value.__aenter__.return_value = mock_response

    #   alert_id_counts, alert_counts = await utils.alert_count(1, "alert1")

    #   assert alert_id_counts == 10
    #   assert alert_counts == 50

    @pytest.mark.asyncio
    @patch('agent.get_chain_id', return_value=1)
    async def test_finding_MALICIOUS_CONTRACT_creation(self, mocker):
        await agent.initialize()

        tx_event = create_transaction_event(
            transaction= {
                "hash": "0",
                "from": "0x34B21846Ca6bF20264242F01CB8220982084EdBd",
                "nonce": 0,
            },
            block = {"number": 0},
            chain_id= 1,
            traces = [],
            logs = []
        )

        # findings = await agent.detect_malicious_contract_tx(w3, tx_event)
        # assert len(findings) == 1, "this should have triggered a finding"
        # finding = next(
        #     (x for x in findings if x.alert_id == "EARLY-ATTACK-DETECTOR-1"),
        #     None,
        # )
        # assert finding.severity == FindingSeverity.Critical
        # assert '0x1e9a6950' in finding.metadata['function_signatures']
