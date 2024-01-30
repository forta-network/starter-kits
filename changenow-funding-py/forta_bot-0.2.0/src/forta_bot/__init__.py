import asyncio
from web3 import Web3, AsyncWeb3
from .blocks import BlockEvent, Block
from .transactions import TransactionEvent, TxEventBlock, Transaction, Receipt
from .traces import Trace, TraceAction, TraceResult
from .alerts import AlertEvent
from .findings import Finding, FindingSeverity, FindingType
from .labels import Label, EntityType
from .jwt import MOCK_JWT
from .utils import BloomFilter, keccak256, snake_to_camel_case
from .di import RootContainer

container = RootContainer()

# provide a way to create as many scan_evm as needed
def create_scan_evm():
  return container.scanning.scan_evm()

scan_ethereum = create_scan_evm()
scan_polygon = create_scan_evm()
scan_bsc = create_scan_evm()
scan_avalanche = create_scan_evm()
scan_arbitrum = create_scan_evm()
scan_optimism = create_scan_evm()
scan_fantom = create_scan_evm()
scan_base = create_scan_evm()

scan_alerts = container.scanning.scan_alerts()
get_alerts = container.alerts.get_alerts()
send_alerts = container.alerts.send_alerts()

decode_jwt = container.jwt.decode_jwt()
get_scanner_jwt = container.jwt.get_scanner_jwt()
fetch_jwt = get_scanner_jwt # alias for backwards compatibility
verify_jwt = container.jwt.verify_jwt()

create_block_event = container.blocks.create_block_event()
create_transaction_event = container.transactions.create_transaction_event()
create_alert_event = container.alerts.create_alert_event()

get_provider = container.scanning.get_provider()
get_transaction_receipt = container.transactions.get_transaction_receipt()
get_bot_id = container.common.get_bot_id()
get_chain_id = container.common.get_chain_id()
get_bot_owner = container.common.get_bot_owner()

run_health_check = container.health.run_health_check()