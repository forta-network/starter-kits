import logging
import unittest
from concurrent.futures import ProcessPoolExecutor

from src.constants import N_WORKERS
from src.main import run_all

logger = logging.getLogger(__name__)



class TestMain(unittest.TestCase):
    def test_run_all_processpool(self):
        """
        This test is to check that the process pool executor works as expected. Furthermore,
        there are some address that should work some problems, as well as some address that had shown
        some type of problem in the past. Executor.shutdown makes this a synchronous call, so the test
        should just complete to be successful
        """
        executor = ProcessPoolExecutor(max_workers=N_WORKERS)

        central_nodes = [
            '0xab01b6fa35daf2d2c6467669ff64a8cc95692514', '0x39e5efbf80a074cd0656599753b04ee616b15d7b',
            '0x41473c5ecde5cfedb9c8ff1e339f985a61f38eee', '0x063a2953fb36cc8ebeac80259dd8a1c972ad778a',
            '0x063a2953fb36cc8ebeac80259dd8a1c972ad778a', '0x6e01af3913026660fcebb93f054345eccd972251',
            '0x5b4ae7d49421705882e999a75ecdfdfe17da7878', '0xe464da92a137365e0bab6b7b122465a36310bfb3'
            '0x62c5af35d11db69c0e8468c70f86f72da0dec3d2',  # Address with empty eth transactions
            '0xee4d48171e0af7506297a3c85d3cf770391ac946',  # Address with 'entity' problem
            '0xc6899b77cfed08d92dbb693da530db9bc26d84c2',  # Address with 'data' problem
            '0xaf4fa85844ab4ad0b162f136e03cf0247123990c',  # 'length of value does not match length of index'
            '0x960d0a37d82b046c699740dc98264b39996d1f0d',  # Expecting value: line 1 column 1 (char 0) '0x7ab1dc2432dfe72a111667f9ce41af7601768938
            
        ]
        for central_node in central_nodes:
            print(central_node)
            executor.map(run_all, (central_node, ))
        executor.shutdown()
    
    def test_warnings(self):
        """
        This test will check that addresses that are supposed to raise a warning do so
        """
        # Not enough neighbors, skipping
        central_node = '0xb631506163da90c8b00f0fec5eab195454b2efdf'
        catch_warning = False
        try:
            _ = run_all(central_node)
        except Warning:
            catch_warning = True
        assert catch_warning, "run_all() should raise a warning for this address"
        # With current attacker level 0.8 there are not enough attackers. Go to next address
        central_node = '0x0e188570adbe7fb6e9483152d9daa181b1d6fd54'
        catch_warning = False
        try:
            _ = run_all(central_node)
        except Warning:
            catch_warning = True
        assert catch_warning, "run_all() should raise a warning for this address"


if __name__ == '__main__':
    unittest.main()
