import eth_abi
from forta_agent import FindingSeverity, create_transaction_event, create_block_event
from eth_utils import keccak, encode_hex
from src.agent import provide_handle_transaction, provide_handle_block

BINANCE_ADDRESS = "0x28c6c06298d514db089934071355e5743bf21d60"
NEW_ADDRESS = "0xe0Dd882d4da747E9448d05584e6B42c6320868BE"
OLD_ADDRESS = "0x145F6FE2196161a82B9b1b31B21eB1c3d7a9387c"
TRANSFER = "Transfer(address,address,uint256)"


def transfer_event(from_addr, to_addr, value: int, contract_address: str):
    hash = keccak(text=TRANSFER)
    data = eth_abi.encode_abi(["uint256"], [value])
    data = encode_hex(data)
    from_ = eth_abi.encode_abi(["address"], [from_addr])
    from_ = encode_hex(from_)
    to = eth_abi.encode_abi(["address"], [to_addr])
    to = encode_hex(to)
    topics = [hash, from_, to]
    return {'topics': topics,
            'data': data,
            'address': contract_address}


class TestFLDAgent:

    def test_returns_zero_finding_if_the_amount_is_small(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BINANCE_ADDRESS,
                'to': NEW_ADDRESS,
                'value': 0,
            },
            'block': {
                'number': 1,
            },
            'logs': [transfer_event(BINANCE_ADDRESS, NEW_ADDRESS, 10, "0xdAC17F958D2ee523a2206206994597C13D831ec7")]})

        block_event = create_block_event({
            'block': {
                'number': 1,
            }
        })

        provide_handle_block()(block_event)
        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 0

    def test_returns_critical_finding_if_new_address_FLD_FUNDING(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BINANCE_ADDRESS,
                'to': NEW_ADDRESS,
                'value': 0,
            },
            'block': {
                'number': 1,
            },
            'logs': [
                transfer_event(BINANCE_ADDRESS, NEW_ADDRESS, 10000000000,
                               "0xdAC17F958D2ee523a2206206994597C13D831ec7")]})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Critical
        assert findings[0].alert_id == "FLD_NEW_FUNDING"

    def test_returns_high_finding_if_the_amount_is_big_erc20_old_address_FLD_FUNDING(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BINANCE_ADDRESS,
                'to': OLD_ADDRESS,
                'value': 0,
            },
            'block': {
                'number': 1,
            },
            'logs': [
                transfer_event(BINANCE_ADDRESS, OLD_ADDRESS, 1000000000000,
                               "0xdAC17F958D2ee523a2206206994597C13D831ec7")]})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.High
        assert findings[0].alert_id == "FLD_FUNDING"

    def test_returns_low_finding_if_the_amount_is_low_erc20_old_address_FLD_FUNDING(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BINANCE_ADDRESS,
                'to': OLD_ADDRESS,
                'value': 0,
            },
            'block': {
                'number': 1,
            },
            'logs': [
                transfer_event(BINANCE_ADDRESS, OLD_ADDRESS, 10000000000,
                               "0xdAC17F958D2ee523a2206206994597C13D831ec7")]})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Low
        assert findings[0].alert_id == "FLD_FUNDING"

    def test_returns_critical_finding_if_new_address_ETH_FLD_FUNDING(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BINANCE_ADDRESS,
                'to': OLD_ADDRESS,
                'value': 10000000000000000000000,
            },
            'block': {
                'number': 1,
            },
            'logs': []})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Critical
        assert findings[0].alert_id == "FLD_FUNDING"

    def test_returns_critical_finding_if_critical_amount_eth_old_address_FLD_FUNDING(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BINANCE_ADDRESS,
                'to': OLD_ADDRESS,
                'value': 100000000000000000000000,
            },
            'block': {
                'number': 1,
            },
            'logs': []})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Critical
        assert findings[0].alert_id == "FLD_FUNDING"

    def test_returns_high_finding_if_high_amount_eth_old_address_FLD_FUNDING(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BINANCE_ADDRESS,
                'to': OLD_ADDRESS,
                'value': 1000000000000000000000,
            },
            'block': {
                'number': 1,
            },
            'logs': []})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.High
        assert findings[0].alert_id == "FLD_FUNDING"

    def test_returns_medium_finding_if_medium_amount_eth_old_address_FLD_FUNDING(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BINANCE_ADDRESS,
                'to': OLD_ADDRESS,
                'value': 100000000000000000000,
            },
            'block': {
                'number': 1,
            },
            'logs': []})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Medium
        assert findings[0].alert_id == "FLD_FUNDING"

    def test_returns_low_finding_if_low_amount_eth_old_address_FLD_FUNDING(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': BINANCE_ADDRESS,
                'to': OLD_ADDRESS,
                'value': 10000000000000000000,
            },
            'block': {
                'number': 1,
            },
            'logs': []})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Low
        assert findings[0].alert_id == "FLD_FUNDING"

    def test_returns_critical_finding_if_critical_amount_eth_old_address_FLD_Laundering(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': OLD_ADDRESS,
                'to': BINANCE_ADDRESS,
                'value': 1000000000000000000000000,
            },
            'block': {
                'number': 1,
            },
            'logs': []})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Critical
        assert findings[0].alert_id == "FLD_Laundering"

    def test_returns_hight_finding_if_critical_amount_eth_old_address_FLD_Laundering(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': OLD_ADDRESS,
                'to': BINANCE_ADDRESS,
                'value': 1000000000000000000000,
            },
            'block': {
                'number': 1,
            },
            'logs': []})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.High
        assert findings[0].alert_id == "FLD_Laundering"

    def test_returns_medium_finding_if_medium_amount_eth_old_address_FLD_Laundering(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': OLD_ADDRESS,
                'to': BINANCE_ADDRESS,
                'value': 100000000000000000000,
            },
            'block': {
                'number': 1,
            },
            'logs': []})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Medium
        assert findings[0].alert_id == "FLD_Laundering"

    def test_returns_low_finding_if_low_amount_eth_old_address_FLD_Laundering(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': OLD_ADDRESS,
                'to': BINANCE_ADDRESS,
                'value': 50000000000000000000,
            },
            'block': {
                'number': 1,
            },
            'logs': []})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Low
        assert findings[0].alert_id == "FLD_Laundering"

    def test_returns_low_finding_if_the_amount_is_low_erc20_old_address_FLD_Laundering(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': OLD_ADDRESS,
                'to': BINANCE_ADDRESS,
                'value': 0,
            },
            'block': {
                'number': 1,
            },
            'logs': [
                transfer_event(OLD_ADDRESS, BINANCE_ADDRESS, 10000000000,
                               "0xdAC17F958D2ee523a2206206994597C13D831ec7")]})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Low
        assert findings[0].alert_id == "FLD_Laundering"

    def test_returns_medium_finding_if_the_amount_is_medium_erc20_old_address_FLD_Laundering(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': OLD_ADDRESS,
                'to': BINANCE_ADDRESS,
                'value': 0,
            },
            'block': {
                'number': 1,
            },
            'logs': [
                transfer_event(OLD_ADDRESS, BINANCE_ADDRESS, 100000000000,
                               "0xdAC17F958D2ee523a2206206994597C13D831ec7")]})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Medium
        assert findings[0].alert_id == "FLD_Laundering"

    def test_returns_high_finding_if_the_amount_is_high_erc20_old_address_FLD_Laundering(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': OLD_ADDRESS,
                'to': BINANCE_ADDRESS,
                'value': 0,
            },
            'block': {
                'number': 1,
            },
            'logs': [
                transfer_event(OLD_ADDRESS, BINANCE_ADDRESS, 1000000000000,
                               "0xdAC17F958D2ee523a2206206994597C13D831ec7")]})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.High
        assert findings[0].alert_id == "FLD_Laundering"

    def test_returns_critical_finding_if_the_amount_is_critical_erc20_old_address_FLD_Laundering(self):
        tx_event = create_transaction_event({
            'transaction': {
                'from': OLD_ADDRESS,
                'to': BINANCE_ADDRESS,
                'value': 0,
            },
            'block': {
                'number': 1,
            },
            'logs': [
                transfer_event(OLD_ADDRESS, BINANCE_ADDRESS, 50000000000000,
                               "0xdAC17F958D2ee523a2206206994597C13D831ec7")]})

        findings = provide_handle_transaction()(tx_event)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.Critical
        assert findings[0].alert_id == "FLD_Laundering"
