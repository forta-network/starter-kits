import logging
import sys
import os

import forta_agent
from forta_agent import get_json_rpc_url
from db.db_utils import db_utils
from db.controller import init_async_db
from web3 import Web3

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

DATABASE = f"https://research.forta.network/database/bot/{web3.eth.chain_id}"
CHAIN_ID = 1
FINDINGS_CACHE = []

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global CHAIN_ID
    try:
        CHAIN_ID = web3.eth.chain_id
    except Exception as e:
        logging.error(f"Error getting chain id: {e}")
        raise e

    global FINDINGS_CACHE
    FINDINGS_CACHE = []

    test_mode = "main" if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV') else "test"
    features_table = init_async_db(test_mode)
    db_utils.set_tables(features_table)

    print(features_table.count_rows())


def handle_alert(alert_event):
    print("handle_alert")
    print(alert_event)


def provide_handle_block(w3):
    logging.debug("provide_handle_block called")

    def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
        logging.debug("handle_block with w3 called")
        return []

    return handle_block


real_handle_block = provide_handle_block(web3)


def handle_block(block_event: forta_agent.block_event.BlockEvent):
    logging.debug("handle_block called")
    return real_handle_block(block_event)
