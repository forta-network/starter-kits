from forta_agent import FindingSeverity, create_transaction_event
import threading
import time
import agent
import utils
from evmdasm import EvmBytecode
from unittest.mock import patch, MagicMock
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

class TestEarlyAttackDetector:
    def test_is_contract_eoa(self):
        assert not utils.is_contract(
            w3, EOA_ADDRESS
        ), "EOA shouldn't be identified as a contract"

    def test_is_contract_contract(self):
        assert utils.is_contract(
            w3, CONTRACT_NO_ADDRESS
        ), "Contract should be identified as a contract"

    def test_opcode_addresses_no_addr(self):
        bytecode = w3.eth.get_code(CONTRACT_NO_ADDRESS)
        opcodes = EvmBytecode(bytecode.hex()).disassemble()
        _, addresses = agent.get_features(w3, opcodes, EOA_ADDRESS)
        assert len(addresses) == 0, "should be empty"

    def test_opcode_addresses_with_addr(self):
        bytecode = w3.eth.get_code(CONTRACT_WITH_ADDRESS)
        opcodes = EvmBytecode(bytecode.hex()).disassemble()
        _, addresses = agent.get_features(w3, opcodes, EOA_ADDRESS)

        assert len(addresses) == 1, "should not be empty"

    def test_storage_addresses_with_addr(self):
        addresses = agent.get_storage_addresses(w3, CONTRACT_WITH_ADDRESS)
        assert len(addresses) == 1, "should not be empty"

    def test_storage_addresses_on_eoa(self):
        addresses = agent.get_storage_addresses(w3, EOA_ADDRESS)
        assert len(addresses) == 0, "should be empty; EOA has no storage"

    def test_calc_contract_address(self):
        contract_address = agent.calc_contract_address(w3, EOA_ADDRESS, 9)
        assert (
            contract_address == "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7"
        ), "should be the same contract address"

    def test_get_function_signatures(self):
        bytecode = w3.eth.get_code(MALICIOUS_CONTRACT)
        opcodes = EvmBytecode(bytecode.hex()).disassemble()
        function_signatures = agent.get_function_signatures(w3, opcodes)
        assert(len(function_signatures)==8)
        assert("0x1e9a6950" in function_signatures)

    def test_get_features(self):
        bytecode = w3.eth.get_code(MALICIOUS_CONTRACT)
        opcodes = EvmBytecode(bytecode.hex()).disassemble()
        features, _ = agent.get_features(w3, opcodes, EOA_ADDRESS)
        assert len(features) == 4572, "incorrect features length obtained"

    def test_get_features(self):
        bytecode = w3.eth.get_code(MALICIOUS_CONTRACT)
        opcodes = EvmBytecode(bytecode.hex()).disassemble()
        features, _ = agent.get_features(w3, opcodes, EOA_ADDRESS)
        assert len(features) == 4572, "incorrect features length obtained"

    # Test for Concurrency and Performance
    def test_concurrent_access_to_get_storage_addresses(self):
        number_of_threads = 10  # Number of threads to simulate concurrency
        threads = []
        results = [None] * number_of_threads  # to store results
        execution_times = [0] * number_of_threads  # to store execution times

        # Worker thread function
        def thread_function(index):
            start_time = time.time()
            result = agent.get_storage_addresses(w3, CONTRACT_WITH_ADDRESS)
            end_time = time.time()

            results[index] = result
            execution_times[index] = end_time - start_time

        # Start threads
        for i in range(number_of_threads):
            thread = threading.Thread(target=thread_function, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Check results and print performance data
        for i in range(number_of_threads):
            print(f'Thread {i}: Execution time {execution_times[i]:.4f} seconds')
            assert isinstance(results[i], set), "Expected result type is set"

    # Test for Concurrency and Performance
    def test_concurrent_access_to_get_storage_addresses_with_none_contract_address(self):
        number_of_threads = 10
        threads = []
        results = [None] * number_of_threads
        execution_times = [0] * number_of_threads

        def thread_function(index):
            start_time = time.time()
            result = agent.get_storage_addresses(w3, EOA_ADDRESS)
            end_time = time.time()

            results[index] = result
            execution_times[index] = end_time - start_time

        for i in range(number_of_threads):
            thread = threading.Thread(target=thread_function, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Check if function returns an empty set
        for i in range(number_of_threads):
            print(f'Thread {i}: Execution time {execution_times[i]:.4f} seconds')
            assert results[i] == set(), "Function should return an empty set for None address"

    def test_concurrent_access_to_get_storage_addresses_with_invalid_address(self):
        number_of_threads = 10
        threads = []
        results = [None] * number_of_threads
        execution_times = [0] * number_of_threads
        exceptions = [None] * number_of_threads  # Array to store exceptions

        def thread_function(index):
            try:
                start_time = time.time()
                result = agent.get_storage_addresses(w3, "12345")
                end_time = time.time()
                results[index] = result
                execution_times[index] = end_time - start_time
            except ValueError as e:
                exceptions[index] = e  # Store the exception

        for i in range(number_of_threads):
            thread = threading.Thread(target=thread_function, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Check for exceptions in each thread
        for i, exception in enumerate(exceptions):
            assert isinstance(exception, ValueError), f"Thread {i} did not raise ValueError as expected"

    @patch('utils.requests.get')
    def test_alert_count_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "alertIds": {"alert1": {"count": 10}},
            "total": {"count": 50}
        }
        mock_get.return_value = mock_response

        alert_id_counts, alert_counts = utils.alert_count(1, "alert1")

        assert alert_id_counts == 10
        assert alert_counts == 50


    def test_finding_MALICIOUS_CONTRACT_creation(self):
        agent.initialize()

        tx_event = create_transaction_event(
            {
                "transaction": {
                    "hash": "0",
                    "from": MALICIOUS_CONTRACT_DEPLOYER,
                    "nonce": MALICIOUS_CONTRACT_DEPLOYER_NONCE,
                },
                "block": {"number": 0, "timestamp": 0},
                "traces": [
                    {
                        "type": "create",
                        "action": {
                            "from": MALICIOUS_CONTRACT_DEPLOYER,
                            "init": w3.eth.get_code(MALICIOUS_CONTRACT),
                            "value": 1,
                        },
                        "result": {"address": MALICIOUS_CONTRACT},
                    }
                ],
                "receipt": {"logs": []},
            }
        )
        findings = agent.detect_malicious_contract_tx(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        finding = next(
            (x for x in findings if x.alert_id == "EARLY-ATTACK-DETECTOR-1"),
            None,
        )
        assert finding.severity == FindingSeverity.Critical
        assert '0x1e9a6950' in finding.metadata['function_signatures']
