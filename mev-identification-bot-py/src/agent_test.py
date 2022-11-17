from forta_agent import FindingSeverity, create_transaction_event
from web3_mock import Web3Mock, CONTRACT_ADDRESS_1, CONTRACT_ADDRESS_2, CONTRACT_ADDRESS_3, CONTRACT_ADDRESS_4
import agent

from constants import TRANSFER_TOPIC

EOA_ADDRESS = "0x000000000000000000000000000000000000000A"

TOKEN_ADDRESS_1 = "0x00000000000000000000000000000000000000AC"
TOKEN_ADDRESS_2 = "0x00000000000000000000000000000000000000BC"
TOKEN_ADDRESS_3 = "0x00000000000000000000000000000000000000CC"
TOKEN_ADDRESS_4 = "0x00000000000000000000000000000000000000DC"
w3 = Web3Mock()

class TestKnownMaliciousAccountFunding:

    def test_mev_identification(self):
        agent.initialize()
       
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 10,
                'to': CONTRACT_ADDRESS_1,
            },
            'block': {
                'number': 0
            },
            'logs': [
                    {'address': TOKEN_ADDRESS_1,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_1[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_2[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_3,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_4,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    }
            ],
            'receipt': {
                'logs': []}
        })
        
        findings = agent.detect_mev(w3, tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "MEV-ACCOUNT"
        assert findings[0].severity == FindingSeverity.Info

    def test_mev_identification_too_few_tx(self):
        agent.initialize()
       
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'value': 10,
                'to': CONTRACT_ADDRESS_1,
            },
            'block': {
                'number': 0
            },
            'logs': [
                    {'address': TOKEN_ADDRESS_1,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_1[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_2[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_2,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_2[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_3,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_3[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_4[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_4,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_1[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_2[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    },
                    {'address': TOKEN_ADDRESS_4,
                     'topics': [TRANSFER_TOPIC, f'0x000000000000000000000000{CONTRACT_ADDRESS_1[2:]}', f'0x000000000000000000000000{CONTRACT_ADDRESS_2[2:]}'],
                     'data': f"0x0000000000000000000000000000000000000000000000000000000004e1521e"
                    }
            ],
            'receipt': {
                'logs': []}
        })
        
        findings = agent.detect_mev(w3, tx_event)
        assert len(findings) == 0, "this should have triggered a finding"


