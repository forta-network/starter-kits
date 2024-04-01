import logging
import sys
import asyncio
from os import environ


from web3 import AsyncWeb3
from forta_bot import get_chain_id, scan_ethereum, run_health_check, TransactionEvent
from constants import TORNADO_CASH_ADDRESSES, TORNADO_CASH_WITHDRAW_TOPIC, TORNADO_CASH_ADDRESSES_HIGH
from findings import FundingTornadoCashFindings
from storage import get_secrets

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

CHAIN_ID = -1

async def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    print("Initializing")
    SECRETS_JSON = await get_secrets()

    global CHAIN_ID
    CHAIN_ID = get_chain_id()
    print("Chain ID: ", CHAIN_ID)

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']


async def detect_funding(w3, transaction_event: TransactionEvent) -> list:
    global CHAIN_ID
    logging.info(
        f"Analyzing transaction {transaction_event.hash} on chain {CHAIN_ID}")
    findings = []

    for log in transaction_event.logs:
        if (log.address.lower() in TORNADO_CASH_ADDRESSES[CHAIN_ID] and TORNADO_CASH_WITHDRAW_TOPIC in log.topics):
            #  0x000000000000000000000000a1b4355ae6b39bb403be1003b7d0330c811747db1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660
            to_address = w3.to_checksum_address(log.data[26:66])
            transaction_count = await w3.eth.get_transaction_count(to_address, block_identifier=transaction_event.block_number)

            if (transaction_count == 0):
                logging.info(
                    f"Identified new account {to_address} on chain {CHAIN_ID}")

                findings.append(FundingTornadoCashFindings.funding_tornado_cash(
                    to_address, "low", CHAIN_ID, transaction_event.hash))
            else:
                logging.info(
                    f"Identified existing account {to_address} on chain {CHAIN_ID}. Wont emit finding.")

        if (log.address.lower() in TORNADO_CASH_ADDRESSES_HIGH[CHAIN_ID] and TORNADO_CASH_WITHDRAW_TOPIC in log.topics):
            #  0x000000000000000000000000a1b4355ae6b39bb403be1003b7d0330c811747db1bc589946f7bfca3950776b499ff5d952768ad0b644c71c5c4a209c04ec2b2a2000000000000000000000000000000000000000000000000003ce4ceb6836660
            to_address = w3.to_checksum_address(log.data[26:66])
            transaction_count = await w3.eth.get_transaction_count(to_address, block_identifier=transaction_event.block_number)

            if (transaction_count < 500):
                logging.info(
                    f"Identified new account {to_address} on chain {CHAIN_ID}")

                findings.append(FundingTornadoCashFindings.funding_tornado_cash(
                    to_address, "high", CHAIN_ID, transaction_event.hash))
            else:
                logging.info(
                    f"Identified older account {to_address} on chain {CHAIN_ID}. Wont emit finding.")

    logging.info(f"Return {transaction_event.transaction.hash}")

    return findings


async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider):
    return await detect_funding(web3, transaction_event)

async def main():
    await initialize()

    await asyncio.gather(
        scan_ethereum({
        'rpc_url': "https://eth-mainnet.g.alchemy.com/v2",
        'rpc_key_id': "ebbd1b21-4e72-4d80-b4f9-f605fee5eb68",
        'local_rpc_url': "1",
        'handle_transaction': handle_transaction
        }),

        run_health_check()
    )


if __name__ == "__main__":
    asyncio.run(main())
