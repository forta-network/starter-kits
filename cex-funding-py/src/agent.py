import asyncio
from web3 import Web3, AsyncWeb3
from os import environ
from forta_bot import scan_ethereum, scan_optimism, scan_polygon, scan_base, scan_arbitrum, TransactionEvent, get_chain_id, run_health_check
from async_lru import alru_cache
from hexbytes import HexBytes
from constants import CEXES

from findings import CEXFundingFinding
from storage import get_secrets


async def initialize():
    SECRETS_JSON = await get_secrets()
    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']

@alru_cache(maxsize=1_000_000)
async def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = await w3.eth.get_code(Web3.to_checksum_address(address))
    return code != HexBytes("0x")


async def is_new_account(w3, address, block_number):
    if address is None:
        return True
    return await w3.eth.get_transaction_count(Web3.to_checksum_address(address), block_number) == 0


async def detect_cex_funding(w3, transaction_event: TransactionEvent) -> list:
    findings = []

    # alert on funding tx from CEXes
    value = transaction_event.transaction.value
    is_new_acc = await is_new_account(w3, transaction_event.to, transaction_event.block_number)
    is_contr = await is_contract(w3, transaction_event.transaction.to)

    if is_new_acc and not is_contr:
        for chainId, chain_data in CEXES.items():
            if chainId == get_chain_id():
                threshold = chain_data["threshold"]
                for address, name in chain_data["exchanges"]:
                    if address.lower() == transaction_event.transaction.from_ and value < threshold:
                        findings.append(
                            CEXFundingFinding(
                                name, transaction_event.transaction.to, value, chainId, transaction_event.hash
                            ).emit_finding()
                        )
                        break

    return findings

async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider):
    return await detect_cex_funding(web3, transaction_event)

async def main():
    await initialize()
    
    await asyncio.gather(
        scan_ethereum({
            'rpc_url': "https://eth-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "420b57cc-c2cc-442c-8fd8-901d70a835a5",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        scan_optimism({
            'rpc_url': "https://opt-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "67374ee9-1b70-485d-be75-83589aa0e10d",
            'local_rpc_url': "10",
            'handle_transaction': handle_transaction
        }),
        scan_polygon({
            'rpc_url': "https://polygon-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "7e311823-448b-41fa-b530-2029b7db21fa",
            'local_rpc_url': "137",
            'handle_transaction': handle_transaction
        }),
        scan_base({
            'rpc_url': "https://base-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "a0532f55-5f90-4c46-a3c0-5ce77b3325bb",
            'local_rpc_url': "8453",
            'handle_transaction': handle_transaction
        }),
        scan_arbitrum({
            'rpc_url': "https://arb-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "fc84b32c-ff10-4eb2-b5d6-70062ea39fa6",
            'local_rpc_url': "42161",
            'handle_transaction': handle_transaction
        }),
        run_health_check()
    )

if __name__ == "__main__":
    asyncio.run(main())