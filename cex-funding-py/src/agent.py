import asyncio
from web3 import Web3, AsyncWeb3
from os import environ
from forta_bot_sdk import scan_ethereum, scan_bsc, scan_optimism, scan_polygon, scan_base, scan_arbitrum, TransactionEvent, get_chain_id, run_health_check
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
            'rpc_key_id': "c795687c-5795-4d63-bcb1-f18b5a391dc4",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        scan_optimism({
            'rpc_url': "https://opt-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "be4bb945-3e18-4045-a7c4-c3fec8dbc3e1",
            'local_rpc_url': "10",
            'handle_transaction': handle_transaction
        }),
        scan_polygon({
            'rpc_url': "https://polygon-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "889fa483-ddd8-4fc0-b6d9-baa1a1a65119",
            'local_rpc_url': "137",
            'handle_transaction': handle_transaction
        }),
        scan_base({
            'rpc_url': "https://base-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "166a510e-edca-4c3d-86e2-7cc49cd90f7f",
            'local_rpc_url': "8453",
            'handle_transaction': handle_transaction
        }),
        scan_arbitrum({
            'rpc_url': "https://arb-mainnet.g.alchemy.com/v2",
            'rpc_key_id': "09037aa1-1e48-4092-ad3b-cf22c89d5b8a",
            'local_rpc_url': "42161",
            'handle_transaction': handle_transaction
        }),
        scan_bsc({
            'rpc_url': "https://intensive-wider-thunder.bsc.quiknode.pro/3385d6a314acba4f5f45bfcc90703ee8d9fd92b9/",
            'local_rpc_url': "56",
            'handle_transaction': handle_transaction
        }),

        run_health_check()
    )

if __name__ == "__main__":
    asyncio.run(main())
