import agent
from web3_mock import Web3Mock

w3 = Web3Mock()


class TestScamDetector:
    def test_initialize(self):
        agent.initialize()
