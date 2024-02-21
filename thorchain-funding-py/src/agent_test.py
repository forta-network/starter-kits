import agent
from forta_agent import FindingSeverity, create_transaction_event, Web3, get_json_rpc_url
from hexbytes import HexBytes
from src.web3_mock import Web3Mock, NEW_EOA, OLD_EOA, NEW_CONTRACT
from src.constants import THORCHAIN_ROUTER_ADDRESS

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

class TestThorchainFundingBot:
    
    def test_transfer_to_contract(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': THORCHAIN_ROUTER_ADDRESS[1],
                'from': "0xEd57Cdd71DaA0672c1DB455963be9D2D5207fa5e", # Random EOA
                'value': "1000000000000000000"
            },
            'block': {
                'number': 1
            },            
            'logs': [{
                'address': THORCHAIN_ROUTER_ADDRESS[1],
                'data': '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000903dc6a35e000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000444f55543a3135333931383235343636344135434635433733343638313936323231344442324145463644333232323531383142423434333730393532433035383939434500000000000000000000000000000000000000000000000000000000',
                'topics':[HexBytes("0xa9cd03aa3c1b4515114539cd53d22085129d495cb9e9f9af77864526240f1bf7"), # TransferOut event
                          HexBytes("0x000000000000000000000000ed57cdd71daa0672c1db455963be9d2d5207fa5e"),
                          HexBytes("0x0000000000000000000000002320a28f52334d62622cc2eafa15de55f9987ed0")] # New Contract
            }]            
        })

        findings = agent.detect_thorchain_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the to is a contract"


    def test_not_transfer_from_thorchain(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': NEW_EOA,
                'from': OLD_EOA,
                'value': "1000000000000000000"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_thorchain_funding(w3, tx_event)
        assert len(findings) == 0, "This should have not triggered a finding as the from is not Thorhain"


    def test_transfer_from_thorchain_to_new_account(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': THORCHAIN_ROUTER_ADDRESS[1],
                'from': "0xEd57Cdd71DaA0672c1DB455963be9D2D5207fa5e", # Random EOA
                'value': "100000000000000000"
            },
            'block': {
                'number': 1
            },
            'logs': [{
                'address': THORCHAIN_ROUTER_ADDRESS[1],
                'data': '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000903dc6a35e000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000444f55543a3135333931383235343636344135434635433733343638313936323231344442324145463644333232323531383142423434333730393532433035383939434500000000000000000000000000000000000000000000000000000000',
                'topics':[HexBytes("0xa9cd03aa3c1b4515114539cd53d22085129d495cb9e9f9af77864526240f1bf7"), # TransferOut event
                          HexBytes("0x000000000000000000000000ed57cdd71daa0672c1db455963be9d2d5207fa5e"),
                          HexBytes("0x00000000000000000000000049a9deca3dca86ab3a029c2ed629ec8477009fee")] # New EOA
            }]
        })

        findings = agent.detect_thorchain_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-THORCHAIN-NEW-ACCOUNT", "This is a tx from Thorchain to a new account"
        assert findings[0].severity == FindingSeverity.Medium, "Severity should be medium"


    def test_low_value_transfer_from_thorchain(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': THORCHAIN_ROUTER_ADDRESS[1],
                'from': "0xEd57Cdd71DaA0672c1DB455963be9D2D5207fa5e", # Random EOA
                'value': "3000000000000000" # Low value
            },
            'block': {
                'number': 1
            },
            'logs': [{
                'address': THORCHAIN_ROUTER_ADDRESS[1],
                'data': '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000903dc6a35e000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000444f55543a3135333931383235343636344135434635433733343638313936323231344442324145463644333232323531383142423434333730393532433035383939434500000000000000000000000000000000000000000000000000000000',
                'topics':[HexBytes("0xa9cd03aa3c1b4515114539cd53d22085129d495cb9e9f9af77864526240f1bf7"), # TransferOut event
                          HexBytes("0x000000000000000000000000ed57cdd71daa0672c1db455963be9d2d5207fa5e"),
                          HexBytes("0x0000000000000000000000004e5b2e1dc63f6b91cb6cd759936495434c7e0000")] # Old EOA
            }]
        })

        findings = agent.detect_thorchain_funding(w3, tx_event)
        assert len(findings) == 1, "This should have triggered a finding"
        assert findings[0].alert_id == "FUNDING-THORCHAIN-LOW-AMOUNT", "This is a low value transfer from Thorchain"
        assert findings[0].severity == FindingSeverity.Low, "Severity should be low"

    
    def test_high_value_transfer_from_thorchain(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': THORCHAIN_ROUTER_ADDRESS[1],
                'from': "0xEd57Cdd71DaA0672c1DB455963be9D2D5207fa5e", # Random EOA
                'value': "300000000000000000" # High value
            },
            'block': {
                'number': 1
            },
            'logs': [{
                'address': THORCHAIN_ROUTER_ADDRESS[1],
                'data': '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000903dc6a35e000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000444f55543a3135333931383235343636344135434635433733343638313936323231344442324145463644333232323531383142423434333730393532433035383939434500000000000000000000000000000000000000000000000000000000',
                'topics':[HexBytes("0xa9cd03aa3c1b4515114539cd53d22085129d495cb9e9f9af77864526240f1bf7"), # TransferOut event
                          HexBytes("0x000000000000000000000000ed57cdd71daa0672c1db455963be9d2d5207fa5e"),
                          HexBytes("0x0000000000000000000000004e5b2e1dc63f6b91cb6cd759936495434c7e0000")] # Old EOA
            }]
        })

        findings = agent.detect_thorchain_funding(w3, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - It is to an address that has sent a transaction and is over the threshold."
