from datetime import datetime

from forta_agent import create_transaction_event, EntityType

import agent
from web3 import Web3
import rlp
from constants import CONTRACT_QUEUE_SIZE
from web3_mock import CONTRACT, EOA_ADDRESS, Web3Mock

w3 = Web3Mock()


class TestSocialEngContractAgent:

    def test_contract_queue_limit(self):
        agent.initialize()
        
        for i in range(CONTRACT_QUEUE_SIZE + 1):

            random_contract_address = TestSocialEngContractAgent.calc_contract_address(w3, EOA_ADDRESS, i)

            contract_interaction_tx_event = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': EOA_ADDRESS,
                    'to': random_contract_address,
                    'nonce': 8,

                },
                'block': {
                    'number': 0,
                    'timestamp': datetime.now().timestamp(),
                },
                'receipt': {
                    'logs': []}
            })

            agent.detect_social_eng_contract_creations(w3, contract_interaction_tx_event)

        assert(len(agent.CONTRACTS_QUEUE) == CONTRACT_QUEUE_SIZE)

    def calc_contract_address(w3, address, nonce) -> str:
        """
        this function calculates the contract address from sender/nonce
        :return: contract address: str
        """

        address_bytes = bytes.fromhex(address[2:].lower())
        return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])

    def test_contract_queue_handling_contract(self):
        agent.initialize()
        contract_interaction_tx_event = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'to': CONTRACT,
                'nonce': 8,

            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })

        agent.detect_social_eng_contract_creations(w3, contract_interaction_tx_event)
        agent.detect_social_eng_contract_creations(w3, contract_interaction_tx_event)


        assert(len(agent.CONTRACTS_QUEUE) == 1)

    def test_contract_queue_handling_EOA(self):
        agent.initialize()
        contract_interaction_tx_event = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'to': EOA_ADDRESS,
                'nonce': 8,

            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })

        agent.detect_social_eng_contract_creations(w3, contract_interaction_tx_event)
    

        assert(len(agent.CONTRACTS_QUEUE) == 0)


    def test_soc_eng_creation_finding(self):
        agent.initialize()
        
        contract_interaction_tx_event = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'to': CONTRACT,
                'nonce': 8,

            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })

        agent.detect_social_eng_contract_creations(w3, contract_interaction_tx_event)

        contract_creation_tx_event = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 9,

            },
            'block': {
                'number': 1,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_social_eng_contract_creations(w3, contract_creation_tx_event)
        assert len(findings) == 1, "should have 1 finding"
        assert findings[0].metadata["anomaly_score"] == 1.0, "should have anomaly score of 1.0"
        assert findings[0].labels[0].toDict()["label"] == 'attacker', "should have attacker as label"
        assert findings[0].labels[0].toDict()["entity"] == EOA_ADDRESS, "should have EOA address as label"
        assert findings[0].labels[0].toDict()["entity_type"] == EntityType.Address, "should have label_type address"
        assert findings[0].labels[0].toDict()["confidence"] == 0.6, "should have 0.3 as label confidence"

        assert findings[0].labels[1].toDict()["label"] == 'attacker_contract', "should have attacker as label"
        assert findings[0].labels[1].toDict()["entity"] == '0x728ad672409da288ca5b9aa85d1a55b803ba97d7', "should have contract address as label"
        assert findings[0].labels[1].toDict()["confidence"] == 0.6, "should have 0.3 as label confidence"
        assert findings[0].labels[1].toDict()["entity_type"] == EntityType.Address, "should have label_type address"

        assert findings[0].labels[2].toDict()["label"] == 'victim', "should have attacker as label"
        assert findings[0].labels[2].toDict()["entity"] == '0x728aeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee97d7', "should have contract address as label"
        assert findings[0].labels[2].toDict()["confidence"] == 0.6, "should have 0.3 as label confidence"
        assert findings[0].labels[2].toDict()["entity_type"] == EntityType.Address, "should have label_type address"



    def test_soc_eng_creation_no_finding_identical_contract(self):
        agent.initialize()
        
        contract_interaction_tx_event = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'to': "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7",
                'nonce': 8,

            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })

        agent.detect_social_eng_contract_creations(w3, contract_interaction_tx_event)

        contract_creation_tx_event = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 9,

            },
            'block': {
                'number': 1,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_social_eng_contract_creations(w3, contract_creation_tx_event)
        assert len(findings) == 0, "should have 0 on identical contract addresses"


    def test_soc_eng_creation_no_finding_no_contract_in_queue(self):
        agent.initialize()

        contract_creation_tx_event = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 9,

            },
            'block': {
                'number': 1,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_social_eng_contract_creations(w3, contract_creation_tx_event)
        assert len(findings) == 0, "should have no finding"