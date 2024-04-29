import logging
import sys
import aiohttp
import asyncio
import random
from os import environ
from web3 import AsyncWeb3
from forta_bot_sdk import get_chain_id, scan_ethereum, scan_polygon, scan_fantom, run_health_check, TransactionEvent
from findings import MaliciousAccountFundingFinding
from storage import get_secrets
from async_lru import alru_cache
from constants import RPC_ENDPOINTS


BOT_ID = "0x9091c581c6e3c11f5485754d2bf0f01a7d6297467c2363f3084ab000274b86c2"

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)


CHAIN_SOURCE_IDS_MAPPING = {
    1: ["etherscan", "etherscan-tags"],  # Ethereum
    137: ["polygon-tags"],  # Polygon
    250: ["fantom-tags"],  # Fantom
}


async def initialize():
    print("Initializing")
    SECRETS_JSON = await get_secrets()

    global CHAIN_ID
    CHAIN_ID = get_chain_id()
    print(f"Chain ID: {CHAIN_ID}")

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']


@alru_cache(maxsize=1_000_000)
async def is_malicious_account(chain_id: int, address: str) -> str:
    source_ids = CHAIN_SOURCE_IDS_MAPPING[chain_id]
    wallet_tag = None

    async with aiohttp.ClientSession() as session:
        for source_id in source_ids:
            labels_url = f"https://api.forta.network/labels/state?entities={address}&sourceIds={source_id}&labels=*xploit*,*hish*,*heist*&limit=1"
            try:
                async with session.get(labels_url) as response:
                    result = await response.json()
                    if isinstance(result.get("events"), list) and len(result["events"]) == 1:
                        wallet_tag = result["events"][0]["label"]["label"]
                        break  # Exit the loop if a tag is found
            except Exception as err:
                logging.error(f"Error obtaining malicious accounts: {err}")
                continue

    return wallet_tag


async def detect_funding(
    transaction_event: TransactionEvent
) -> list:
    findings = []
    rpc_url = random.choice(RPC_ENDPOINTS[CHAIN_ID])

    w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc_url))

    from_ = transaction_event.transaction.from_.lower()
    malicious_account = await is_malicious_account(CHAIN_ID, from_)

    if transaction_event.transaction.value > 0 and malicious_account is not None:
        findings.append(
            MaliciousAccountFundingFinding.funding(
                transaction_event.hash,
                transaction_event.transaction.to,
                from_,
                malicious_account,
                CHAIN_ID,
                BOT_ID
            )
        )

    return findings


async def handle_transaction(
    transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider
):
    return await detect_funding(transaction_event)

async def main():
    print("Starting")
    await initialize()

    await asyncio.gather(
        scan_ethereum({
            'rpc_url': "https://rpc.ankr.com/eth",
            # 'rpc_key_id': "c795687c-5795-4d63-bcb1-f18b5a391dc4",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        # scan_fantom({
        #     'rpc_url': "https://rpc.ankr.com/fantom",
        #     # 'rpc_key_id': "be4bb945-3e18-4045-a7c4-c3fec8dbc3e1",
        #     'local_rpc_url': "250",
        #     'handle_transaction': handle_transaction
        # }),
        # scan_polygon({
        #     'rpc_url': "https://rpc.ankr.com/polygon",
        #     # 'rpc_key_id': "889fa483-ddd8-4fc0-b6d9-baa1a1a65119",
        #     'local_rpc_url': "137",
        #     'handle_transaction': handle_transaction
        # }),

        run_health_check()
    )


if __name__ == "__main__":
    asyncio.run(main())
