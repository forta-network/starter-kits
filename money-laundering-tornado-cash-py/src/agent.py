import logging
import sys

import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3
from os import environ

from src.constants import (TORNADO_CASH_ACCOUNTS_QUEUE_SIZE,
                           TORNADO_CASH_ADDRESSES, TORNADO_CASH_TRANSFER_AMOUNT_THRESHOLDS,
                           TORNADO_CASH_DEPOSIT_TOPIC,)
from src.findings import MoneyLaunderingTornadoCashFindings
from src.storage import s3_client, dynamo_table, get_secrets, bucket_name

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


s3 = None
dynamo = None
secrets = None
item_id_prefix = ""

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    global s3
    global dynamo
    global secrets

    try:
        # initialize dynamo DB
        if dynamo is None:
            secrets = get_secrets()
            s3 = s3_client(secrets)
            dynamo = dynamo_table(secrets)
            logging.info("Initialized dynamo DB successfully.")
    except Exception as e:
        logging.error("Error getting chain id: {e}")
        raise e

    environ["ZETTABLOCK_API_KEY"] = secrets['apiKeys']['ZETTABLOCK']


def put_tc_ml(account_queue: list):
    global CHAIN_ID
    global BOT_VERSION

    logging.debug(
        f"putting tornado cash money laundering object in dynamo DB")

    itemId = f"{item_id_prefix}|{CHAIN_ID}|ml_tct"

    response = dynamo.put_item(Item={
        "itemId": itemId,
        "sortKey": "tc-ml",
        "accountQueue": account_queue
    })

    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        logging.error(f"Error putting alert in dynamoDB: {response}")
        Utils.ERROR_CACHE.add(Utils.alert_error(
            f'dynamo.put_item HTTPStatusCode {response["ResponseMetadata"]["HTTPStatusCode"]}', "agent.put_tc_ml", ""))
        return
    else:
        logging.info(f"Successfully put alert in dynamoDB: {response}")
        return


def read_tc_ml() -> list:
    global CHAIN_ID

    account_queue = []

    itemId = f"{item_id_prefix}|{CHAIN_ID}|ml_tct"

    logging.info(
        f"Reading tornado cash money laundering object from itemId {itemId}")
    logging.info(f"Dynamo : {dynamo}")
    response = dynamo.query(KeyConditionExpression='itemId = :id',
                            ExpressionAttributeValues={
                                ':id': itemId
                            }
                            )

    items = response.get('Items', [])

    if len(items) > 0:
        account_queue = items[0]['accountQueue']

    return account_queue


def detect_money_laundering(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    isTornadoDeposit = False
    cur_account_queue = []
    db_account_queue = []

    logging.info(
        f"Analyzing transaction {transaction_event.transaction.hash} on chain {w3.eth.chain_id}")

    findings = []
    account = Web3.toChecksumAddress(transaction_event.from_)

    if transaction_event.to is None:
        return findings

    for log in transaction_event.logs:
        if (transaction_event.transaction.value is not None and transaction_event.transaction.value > 0 and
           log.address in TORNADO_CASH_ADDRESSES and TORNADO_CASH_DEPOSIT_TOPIC in log.topics):

            isTornadoDeposit = True

            if not any(d['account'] == account for d in cur_account_queue):
                cur_account_queue.append(
                    {"value": TORNADO_CASH_ADDRESSES[log.address], "account": account})
            else:
                for d in cur_account_queue:
                    if d['account'] == account:
                        d['value'] += TORNADO_CASH_ADDRESSES[log.address]

            logging.info(
                f"Identified account {account} on chain {w3.eth.chain_id}")

    if isTornadoDeposit:
        db_account_queue = read_tc_ml()

        # merge records from db with the new account queue
        for d in cur_account_queue:
            if not any(db_d['account'] == d['account'] for db_d in db_account_queue):
                db_account_queue.append(d)

            else:
                for db_d in db_account_queue:
                    if db_d['account'] == d['account']:
                        db_d['value'] += d['value']

        #  maintain a size
        if len(db_account_queue) > TORNADO_CASH_ACCOUNTS_QUEUE_SIZE:
            db_account_queue.pop(0)

        put_tc_ml(db_account_queue)

    if any(d['account'] == account for d in db_account_queue):
        # if the account's value is greater than the threshold, then we have a finding
        for d in db_account_queue:
            if d['account'] == account:
                if d['value'] >= TORNADO_CASH_TRANSFER_AMOUNT_THRESHOLDS[w3.eth.chain_id]["high"]:
                    findings.append(MoneyLaunderingTornadoCashFindings.possible_money_laundering_tornado_cash(
                        account, d['value'], CHAIN_ID))
                elif d['value'] >= TORNADO_CASH_TRANSFER_AMOUNT_THRESHOLDS[w3.eth.chain_id]["medium"]:
                    findings.append(MoneyLaunderingTornadoCashFindings.possible_money_laundering_tornado_cash_medium(
                        account, d['value'], CHAIN_ID))
                elif d['value'] >= TORNADO_CASH_TRANSFER_AMOUNT_THRESHOLDS[w3.eth.chain_id]["low"]:
                    findings.append(MoneyLaunderingTornadoCashFindings.possible_money_laundering_tornado_cash_low(
                        account, d['value'], CHAIN_ID))

    logging.info(f"Return {transaction_event.transaction.hash}")

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_money_laundering(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
