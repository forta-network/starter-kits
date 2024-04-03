import logging
import sys
from os import environ
from functools import lru_cache

import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3

from datetime import datetime, timedelta

from src.constants import MIN_NONCE, MIN_AGE_IN_DAYS, MIN_AGE_IN_DAYS_FOR_CONTRACT_DEPLOYMENT, CACHE_EXPIRY_IN_DAYS
from src.findings import PositiveReputationFindings
from src.blockexplorer import BlockExplorer
from src.storage import get_secrets, dynamo_table, s3_client

SECRETS_JSON = get_secrets()

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
blockexplorer = BlockExplorer(web3.eth.chain_id)

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

s3 = None
dynamo = None
item_id_prefix = ""

CHAIN_ID = -1


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global s3
    global dynamo

    try:
        # initialize dynamo DB
        if dynamo is None:
            secrets = get_secrets()
            s3 = s3_client(secrets)
            dynamo = dynamo_table(secrets)
            logging.info("Initialized dynamo DB successfully.")
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']


def put_first_tx(address: str, first_tx_datetime: datetime):
    global CHAIN_ID

    itemId = f"{item_id_prefix}|{CHAIN_ID}|first_tx|{address}"
    logging.debug(f"itemId: {itemId}")
    sortId = f"{address}"
    logging.debug(f"sortId: {sortId}")

    expiry_offset = CACHE_EXPIRY_IN_DAYS * 24 * 60 * 60

    expiresAt = int(datetime.now().timestamp()) + int(expiry_offset)
    logging.debug(f"expiresAt: {expiresAt}")
    response = dynamo.put_item(Item={
        "itemId": itemId,
        "sortKey": sortId,
        "first_tx_datetime": str(int(first_tx_datetime.timestamp())),
        "expiresAt": expiresAt
    })

    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        logging.error(f"Error putting first tx in dynamoDB: {response}")
        return
    else:
        logging.info(f"Successfully put first tx in dynamoDB: {response}")
        return

@lru_cache(maxsize=64000)
def read_first_tx(address: str):
    global CHAIN_ID

    itemId = f"{item_id_prefix}|{CHAIN_ID}|first_tx|{address}"
    logging.debug(f"Reading entity clusters for address {address} from itemId {itemId}")
    logging.debug(f"Dynamo : {dynamo}")
    response = dynamo.query(KeyConditionExpression='itemId = :id',
                            ExpressionAttributeValues={
                                ':id': itemId
                            }
                            )

    # Print retrieved item
    items = response.get('Items', [])
    logging.debug(f"Items retrieved: {len(items)}")
    for item in items:
        logging.debug(f"Item retrieved: {item}")
        return datetime.fromtimestamp(int(item["first_tx_datetime"]))

    return None


def put_pos_rep_address(address: str):
    global CHAIN_ID

    itemId = f"{item_id_prefix}|{CHAIN_ID}|pos_rep|{address}"
    logging.debug(f"itemId: {itemId}")
    sortId = f"{address}"
    logging.debug(f"sortId: {sortId}")

    expiry_offset = CACHE_EXPIRY_IN_DAYS * 24 * 60 * 60

    expiresAt = int(datetime.now().timestamp()) + int(expiry_offset)
    logging.debug(f"expiresAt: {expiresAt}")
    response = dynamo.put_item(Item={
        "itemId": itemId,
        "sortKey": sortId,
        "expiresAt": expiresAt
    })

    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        logging.error(f"Error putting pos rep address in dynamoDB: {response}")
        return
    else:
        logging.info(f"Successfully put pos rep address in dynamoDB: {response}")
        return


def read_pos_rep(address: str) -> bool:
    global CHAIN_ID

    itemId = f"{item_id_prefix}|{CHAIN_ID}|pos_rep|{address}"
    logging.debug(f"Reading entity clusters for address {address} from itemId {itemId}")
    logging.debug(f"Dynamo : {dynamo}")
    response = dynamo.query(KeyConditionExpression='itemId = :id',
                            ExpressionAttributeValues={
                                ':id': itemId
                            }
                            )

    # Print retrieved item
    items = response.get('Items', [])
    logging.debug(f"Items retrieved: {len(items)}")
    for item in items:
        logging.debug(f"Item retrieved: {item}")
        return True
    return False



def detect_positive_reputation(w3, blockexplorer, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global CHAIN_ID
    logging.info(f"Analyzing transaction {transaction_event.transaction.hash} on chain {CHAIN_ID}")

    findings = []
    address = transaction_event.transaction.from_.lower()

    # Get the first transaction of the sender
    first_tx = read_first_tx(address)
    if first_tx is None:
        logging.info(f"Checking first tx of address with blockexplorer {address}")
        first_tx = blockexplorer.get_first_tx(address)

        # if the block explorer fails to return the first tx, we skip the check
        if first_tx is None:
            return findings
        
        put_first_tx(address, first_tx)

    # Check if the first transaction is older than the minimum age
    if first_tx < datetime.now() - timedelta(days=MIN_AGE_IN_DAYS): 
        if not read_pos_rep(address):
            put_pos_rep_address(address)

            # Append findings based on the nonce condition
            if transaction_event.transaction.nonce >= MIN_NONCE:
                findings.append(PositiveReputationFindings.positive_reputation(address, CHAIN_ID))
            else:
                findings.append(PositiveReputationFindings.positive_reputation_by_age(address, CHAIN_ID))
    elif first_tx < datetime.now() - timedelta(days=MIN_AGE_IN_DAYS_FOR_CONTRACT_DEPLOYMENT):
        if not read_pos_rep(address):

            if blockexplorer.has_deployed_high_tx_count_contract(address, CHAIN_ID):
                put_pos_rep_address(address)
                findings.append(PositiveReputationFindings.positive_reputation_by_contract_deployment(address, CHAIN_ID))


    return findings



def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_positive_reputation(w3, blockexplorer, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
