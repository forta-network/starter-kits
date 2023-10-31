import logging
from datetime import datetime
import os
import random
import time
import forta_agent
from web3 import Web3
from forta_agent import get_json_rpc_url, Finding
from concurrent.futures import ThreadPoolExecutor

from src.main import run_all
from src.constants import attacker_bots, ATTACKER_CONFIDENCE, N_WORKERS, MAX_FINDINGS, HOURS_BEFORE_REANALYZE, PERCENTAGE_ATTACKERS, MAX_FINDINGS_PER_ADDRESS
from src.storage import get_secrets, dynamo_table


# If we are in production, we log to the console. Otherwise, we log to a file
if 'production' in os.environ.get('NODE_ENV', ''):
    logging.basicConfig(level=logging.INFO, 
                        format='%(levelname)s:%(asctime)s:%(name)s:%(lineno)d:%(message)s')
    ENV = 'prod'
else:
    logging.basicConfig(filename=f"logs.log", level=logging.INFO, 
                        format='%(levelname)s:%(asctime)s:%(name)s:%(lineno)d:%(message)s')
    ENV = 'test'
logger = logging.getLogger(__name__)

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


def run_all_extended(central_node, alert_event, web3):
    global secrets
    try:
        attackers_df, graph_statistics, attackers_df_global = run_all(central_node, secrets=secrets, web3=web3)
    except Warning as w:
        logger.warning(f"{central_node}:\tWarning running run_all in a thread: {w}")
        return []
    except Exception as e:
        logger.error(f"{central_node}:\tError running run_all in a thread: {e}", exc_info=True)
        # We need to raise the exception to expose error to the scan node
        if 'production' in os.environ.get('NODE_ENV', ''):
            raise e
        return []
    # Now we put things into a list of findings
    all_findings_list = []
    finding_dict = {
            'name': 'scammer-label-propagation',
            'description': 'Address marked as scammer by label propagation',
            'alert_id': 'SCAMMER-LABEL-PROPAGATION-1',
            'severity': forta_agent.FindingSeverity.High,
            'type': forta_agent.FindingType.Scam
        }
    logger.info(f"{central_node}:\t{graph_statistics} new attackers found")
    # We will only consider the model as working if it has less or equal than MAX_FINDINGS_PER_ADDRESS findings. Otherwise we remove all findings
    if attackers_df.shape[0] <= MAX_FINDINGS_PER_ADDRESS:
        for row_idx in range(attackers_df.shape[0]):
            attacker_info = attackers_df.iloc[row_idx]
            logger.info(f'{central_node}:\tNew attacker info: {attacker_info}')
            metadata = {
                    'central_node': central_node,
                    'central_node_alert_id': alert_event.alert.alert_id,
                    'central_node_alert_name': alert_event.alert.name,
                    'central_node_alert_hash': alert_event.alert.hash,
                    'graph_statistics': str(graph_statistics),
                    'model_confidence': attacker_info['n_predicted_attacker']/10 * attacker_info['mean_probs_attacker'],
                }
            label_dict = {
                'entity': attacker_info.name,
                'label': 'scammer-eoa',
                'confidence': attacker_info['n_predicted_attacker']/10 * attacker_info['mean_probs_attacker'],
                'entity_type': forta_agent.EntityType.Address,
                'metadata': metadata
            }
            finding_dict['labels'] = [forta_agent.Label(label_dict)]
            finding_dict['metadata'] = metadata
            finding_dict['description'] = f"{attacker_info.name} marked as scammer by label propagation"
            finding_dict['addresses'] = [attacker_info.name, central_node]
            all_findings_list.append(Finding(finding_dict))
    else:
        logger.info(f"{central_node}:\tToo many attackers found: {attackers_df.shape[0]}. Not adding any findings")
    if alert_event.alert.alert_id in ['SCAM-DETECTOR-NATIVE-ICE-PHISHING', "SCAM-DETECTOR-ICE-PHISHING"]:
        logger.info(f"{central_node}:\tAlert {alert_event.alert.alert_id}. Not running global model")
        return all_findings_list
    # Prepare the dataset for the global model
    finding_dict_global = finding_dict.copy()
    finding_dict_global['alert_id'] = 'SCAMMER-LABEL-PROPAGATION-2'
    finding_dict_global['name'] = 'scammer-label-propagation-global'
    finding_dict_global['description'] = 'Address marked as scammer by label propagation (global model)'
    # Restarting severity
    finding_dict_global['severity'] = forta_agent.FindingSeverity.High
    if attackers_df_global.shape[0] <= MAX_FINDINGS_PER_ADDRESS:
        for row_idx in range(attackers_df_global.shape[0]):
            attacker_info = attackers_df_global.iloc[row_idx]
            logger.info(f'{central_node}:\tNew attacker info global: {attacker_info}')
            metadata = {
                    'central_node': central_node,
                    'central_node_alert_id': alert_event.alert.alert_id,
                    'central_node_alert_name': alert_event.alert.name,
                    'central_node_alert_hash': alert_event.alert.hash,
                    'graph_statistics': str(graph_statistics),
                    'model_confidence': str(attacker_info['p_attacker']),
                }
            label_dict = {
                    'entity': attacker_info.name,
                    'label': 'scammer-eoa',
                    'confidence': str(attacker_info['p_attacker']),
                    'entity_type': forta_agent.EntityType.Address,
                    'metadata': metadata
                }
            finding_dict_global['labels'] = [forta_agent.Label(label_dict)]
            finding_dict_global['metadata'] = metadata
            finding_dict_global['description'] = f"{attacker_info.name} marked as scammer by label propagation (global model)"
            finding_dict_global['addresses'] = [attacker_info.name, central_node]
            all_findings_list.append(Finding(finding_dict_global))
    else:
        logger.info(f"{central_node}:\tToo many attackers found for global model: {attackers_df_global.shape[0]}. Not adding any findings")
    return all_findings_list
        
        
def initialize():
    global executor
    executor = ThreadPoolExecutor(max_workers=N_WORKERS)
    global global_futures
    global_futures = {}
    global global_alerts
    global_alerts = []
    global secrets
    secrets = get_secrets()
    global dynamo
    dynamo = dynamo_table(secrets)

    subscription_json = []
    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id
    for bot in attacker_bots:
        subscription_json.append({"botId": bot, "chainId": CHAIN_ID})
    alert_config = {"alertConfig": {"subscriptions": subscription_json}}
    logger.info(f"Initializing scammer label propagation bot. Subscribed to bots successfully: {alert_config}")
    return alert_config


def put_address_in_dynamo(central_node):
    global dynamo
    global ENV
    itemId = f"scam-label-propagation|addresses|{ENV}|{CHAIN_ID}|{central_node}"
    sortId = str(random.randint(0, 1000000))
    expiring  = int(datetime.now().timestamp()) + int(HOURS_BEFORE_REANALYZE * 3600)
    response = dynamo.put_item(
        Item={"itemId": itemId, 
                "sortKey": sortId, 
                "expiresAt": expiring}
                )
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        logging.error(f"Error putting address in dynamoDB: {response}")
    return


def get_address_from_dynamo(central_node):
    global dynamo
    global ENV
    itemId = f"scam-label-propagation|addresses|{ENV}|{CHAIN_ID}|{central_node}"
    response = dynamo.query(KeyConditionExpression='itemId = :id',
                            ExpressionAttributeValues={':id': itemId})
    items = response.get('Items', [])
    return len(items)


def provide_handle_alert(w3):
    logger.debug("provide_handle_alert called")

    def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
        logger.debug("handle_alert inner called")
        logger.debug(f"AlertId:{alert_event.alert_id};\tName:{alert_event.name};\tAlertHash:{alert_event.hash};\tBotId{alert_event.bot_id};\tAddress:{alert_event.alert.addresses}")
        for label in alert_event.alert.labels:
            logger.debug(f"Entity:{label.entity};\tConfidence:{label.confidence};\tMetadata:{label.metadata};\tLabel:{label.label};\tEntityType:{label.entity_type}")
        t = time.time()
        global executor
        global global_futures

        list_of_addresses = []
        if alert_event.alert.alert_id in ['SCAM-DETECTOR-ADDRESS-POISONING', 'SCAM-DETECTOR-SCAMMER-ASSOCIATION']:
            logger.debug(f"Invalid alert id. Addresses: {';'.join([label.entity for label in alert_event.alert.labels])}")
            return []
        for label in alert_event.alert.labels:
            # if label.confidence >= ATTACKER_CONFIDENCE and label.entity_type == forta_agent.EntityType.Address:
            try:
                if label.confidence >= ATTACKER_CONFIDENCE and label.metadata['address_type'] == 'EOA':
                    logger.debug(f"Entity:{label.entity};\tConfidence:{label.confidence};\tMetadata:{label.metadata};\tLabel:{label.label};\tEntityType:{label.entity_type}")
                    list_of_addresses.append(label.entity)
            except KeyError:
                logger.error(f"Error getting address type from metadata: {label.metadata}")
                continue
        list_of_addresses = list(set(list_of_addresses))
        for address in list_of_addresses:
            n_times_already_analyzed = get_address_from_dynamo(address)
            # It doesn't need to run more than 3 times accross instances, and it doesn't need to run if it is already running
            if n_times_already_analyzed < 3 and address not in global_futures.keys():
                logger.info(f"Adding address {address} to the pool. It has been analyzed {n_times_already_analyzed} times in the last {HOURS_BEFORE_REANALYZE} hours")
                put_address_in_dynamo(address)
                global_futures[address] = executor.submit(run_all_extended, address, alert_event, web3)
            else:
                logger.info(f"Address {address} already analyzed {n_times_already_analyzed} times in the last {HOURS_BEFORE_REANALYZE} hours. Skipping")
        logger.info(f"Alert {alert_event.alert.alert_id}:\t{time.time() - t:.10f} s. {len(list_of_addresses)} addresses: {';'.join(list_of_addresses)}")
        return []

    return handle_alert


real_handle_alert = provide_handle_alert(web3)


def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
    logger.debug("handle_alert called")
    return real_handle_alert(alert_event)


def provide_handle_block(w3):
    logger.debug("provide_handle_block called")

    def handle_block(block_event) -> list:
        logger.debug("handle_block inner called")
        t = time.time()
        global global_futures
        global global_alerts

        completed_futures = []
        running_futures = 0
        pending_futures = 0
        for address, future in global_futures.items():
            if future.running():
                running_futures += 1
            elif future.done():
                try:
                    # A completed future may have a warning/error. We need to remove it from the global list anyway
                    completed_futures.append(address)
                    global_alerts += future.result()
                except Exception as e:
                    logger.error(f"Exception {e} occurred while collecting results from address {address}")
            else:
                pending_futures += 1
        for address in completed_futures:
            global_futures.pop(address)
        # We return the first MAX_FINDINGS findings, and remove them from the list. Otherwise
        # we cache them in global alerts and will return them in the next block
        alerts = global_alerts[:MAX_FINDINGS]
        global_alerts = global_alerts[MAX_FINDINGS:]
        # Only log if there are findings, we are debugging or there is something running in the background
        if len(alerts) > 0 or running_futures > 0 or pending_futures > 0:
            logger.info(f"Block {block_event.block_number}:\tRF:{running_futures};PF:{pending_futures};\t {time.time() - t:.10f} s;\t{len(alerts)} findings")
        else:
            logger.debug(f"Block {block_event.block_number}:\tRF:{running_futures};PF:{pending_futures};\t {time.time() - t:.10f} s;\tNo findings")
        return alerts

    return handle_block


real_handle_block = provide_handle_block(web3)

def handle_block(block_event) -> list:
    logger.debug("handle_block called")
    return real_handle_block(block_event)
