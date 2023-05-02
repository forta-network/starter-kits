import logging
import unittest
from concurrent.futures import ProcessPoolExecutor

from src.constants import N_WORKERS
from src.main import run_all

logger = logging.getLogger(__name__)



class TestMain(unittest.TestCase):
    def test_run_all(self):
        executor = ProcessPoolExecutor(max_workers=N_WORKERS)

        central_nodes = [
            '0xab01b6fa35daf2d2c6467669ff64a8cc95692514', '0x39e5efbf80a074cd0656599753b04ee616b15d7b',
            '0x41473c5ecde5cfedb9c8ff1e339f985a61f38eee', '0x063a2953fb36cc8ebeac80259dd8a1c972ad778a',
            '0x063a2953fb36cc8ebeac80259dd8a1c972ad778a', '0x6e01af3913026660fcebb93f054345eccd972251',
            '0x5b4ae7d49421705882e999a75ecdfdfe17da7878', '0xe464da92a137365e0bab6b7b122465a36310bfb3'
        ]
        for central_node in central_nodes:
            print(central_node)
            executor.map(run_all, (central_node, ))
        executor.shutdown()

if __name__ == '__main__':
    unittest.main()
