import time
import torch
import logging
import requests
import numpy as np
import pandas as pd
from datetime import datetime
from forta_agent import get_labels

from src.constants import attacker_bots, victim_bots, SIMULTANEOUS_ADDRESSES, MIN_NEIGHBORS, MAX_NEIGHBORS
from src.storage import get_secrets, dynamo_table


logger = logging.getLogger(__name__)




def collect_data_zettablock(central_node, secrets):
    t = time.time()
    n_retries = 3
    API_key = secrets['apiKeys']['ZETTABLOCK']
    global dynamo
    dynamo = dynamo_table(secrets)

    list_of_addresses = get_list_of_addresses_zettablock(central_node, API_key, n_retries=n_retries)
    erc20_data = get_erc20_data_zettablock(list_of_addresses, API_key=API_key, n_retries=n_retries)
    eth_data = get_eth_data_zettablock(list_of_addresses, API_key=API_key, n_retries=n_retries)
    data = {**erc20_data, **eth_data}
    logger.info(f'{central_node}:\tData collected; Time needed: {time.time() - t:.2f} s')
    return data


def get_list_of_addresses_zettablock(central_node, API_key, n_retries=3):
    # Fist step is to query all the addresses that had some interaction with the central node
    all_addresses_url = "https://api.zettablock.com/api/v1/dataset/sq_4afc4b8183174d1dbbef855a0144efd4/graphql"  # 1 year
    all_addresses_query = """
    query associatedAddresses($address: String) {
      receiver: records(from_address: $address) {
        to_address
      }
      sender: records(to_address: $address) {
        from_address
      }
    }
    """
    all_addresses_variables = {"address": central_node}
    payload = {"query": all_addresses_query, "variables": all_addresses_variables}
    headers = {
        "accept": "application/json",
        "X-API-KEY": API_key,
        "content-type": "application/json"
    }
    # Need to add a retry mechanism in case the request fails
    for i in range(n_retries):
        try:
            response = requests.post(all_addresses_url, json=payload, headers=headers)
            if response.status_code != 200:
                raise ValueError(f"Status code: {response.status_code}")
        except Exception as e:
            logger.debug('Retrying')
            if i == (n_retries - 1):
                raise ValueError(f'{central_node}:\tGetting all addresses failed. {response}\n{e}', exec_info=True)
        else:
            break
    
    list_of_addresses = list(set([a['from_address'] for a in response.json()['data']['sender']] + 
                                 [a['to_address'] for a in response.json()['data']['receiver']]))
    # Central node is not considered in the above query, so we add it manually
    list_of_addresses += [central_node]
    if len(list_of_addresses) < MIN_NEIGHBORS:
        raise Warning(f'{central_node}:\tNot enough neighbors, skipping. Number of neighbors: {len(list_of_addresses)}')
    if len(list_of_addresses) > MAX_NEIGHBORS:
        raise Warning(f'{central_node}:\tToo many neighbors, skipping')
    return list_of_addresses


def get_erc20_data_zettablock(list_of_addresses, API_key, n_retries=3):
    # ERC20 obtaining the data
    erc20_url = "https://api.zettablock.com/api/v1/dataset/sq_e0c40a9d7531406fad1deef330c9ec66/graphql"
    erc20_query = """
        query associatedAddresses($address: String!) {
        receiver: records(from_address: $address, limit: 500) {
            data_creation_date
            from_address
            to_address
            sum_price_in_usd
            max_price_in_usd
            n_erc20_transactions_together
        }
        sender: records(to_address: $address, limit: 500) {
            data_creation_date
            from_address
            to_address
            sum_price_in_usd
            max_price_in_usd
            n_erc20_transactions_together
        }
        }
    """
    all_erc20_transactions = []
    headers = {
            "accept": "application/json",
            "X-API-KEY": API_key,
            "content-type": "application/json"
        }
    for address in list_of_addresses:
        variables = {"address":address}
        payload = {"query": erc20_query, "variables": variables}
        for i in range(n_retries):
            try:
                response = requests.post(erc20_url, json=payload, headers=headers)
                if response.status_code != 200:
                    raise ValueError(f"Status code: {response.status_code}")
            except Exception as e:
                logger.debug('Retrying')
            else:
                all_erc20_transactions.append(pd.DataFrame(response.json()['data']['receiver']))
                all_erc20_transactions.append(pd.DataFrame(response.json()['data']['sender']))
                break
        # If the request fails n_retries times, it will skip the address
        if i == (n_retries - 1):
            continue
    
    all_erc20_transactions_df = pd.concat(all_erc20_transactions).reset_index(drop=True).drop_duplicates()

    erc20_out = all_erc20_transactions_df[
        all_erc20_transactions_df['from_address'].isin(list_of_addresses)].groupby('from_address').agg(
        {'to_address': 'nunique', 'sum_price_in_usd': 'sum', 'max_price_in_usd': 'max', 'n_erc20_transactions_together': 'sum'}).reset_index()
    erc20_out['avg_usd_out_erc20'] = erc20_out['sum_price_in_usd'] / erc20_out['n_erc20_transactions_together']
    erc20_out.columns = ['address', 'n_unique_addresses_out', 'total_usd_out_erc20', 'max_usd_out_erc20', 'n_transactions_out_erc20', 'avg_usd_out_erc20']

    erc20_in = all_erc20_transactions_df[
        all_erc20_transactions_df['to_address'].isin(list_of_addresses)].groupby('to_address').agg(
        {'from_address': 'nunique', 'sum_price_in_usd': 'sum', 'max_price_in_usd': 'max', 'n_erc20_transactions_together': 'sum'}).reset_index()
    erc20_in['avg_usd_in_erc20'] = erc20_in['sum_price_in_usd'] / erc20_in['n_erc20_transactions_together']
    erc20_in.columns = ['address', 'n_unique_addresses_in', 'total_usd_in_erc20', 'max_usd_in_erc20', 'n_transactions_in_erc20', 'avg_usd_in_erc20']

    all_erc20_transactions_temp = all_erc20_transactions_df[all_erc20_transactions_df['to_address'].isin(list_of_addresses)]
    all_erc20_transactions_temp = all_erc20_transactions_temp[all_erc20_transactions_temp['from_address'].isin(list_of_addresses)]
    all_erc20_transactions_temp = all_erc20_transactions_temp.groupby(['from_address', 'to_address']).agg(
        {'sum_price_in_usd': 'sum', 'max_price_in_usd': 'max', 'n_erc20_transactions_together': 'sum'}).reset_index()
    all_erc20_transactions_temp['avg_usd_erc20'] = all_erc20_transactions_temp['sum_price_in_usd'] / all_erc20_transactions_temp['n_erc20_transactions_together']
    all_erc20_transactions_temp.columns = ['from_address', 'to_address', 'total_usd_together_erc20', 'max_usd_together_erc20', 
                                           'n_transactions_together_erc20', 'avg_usd_together_erc20']    

    erc20_data = {}
    # Ordering columns
    erc20_data['all_erc20_transactions'] = all_erc20_transactions_temp[['from_address', 'to_address', 'n_transactions_together_erc20',
       'max_usd_together_erc20', 'avg_usd_together_erc20','total_usd_together_erc20']]
    erc20_data['erc20_out'] = erc20_out[['address', 'n_transactions_out_erc20', 'max_usd_out_erc20', 'avg_usd_out_erc20', 'total_usd_out_erc20']]
    erc20_data['erc20_in'] = erc20_in[['address', 'n_transactions_in_erc20', 'max_usd_in_erc20', 'avg_usd_in_erc20', 'total_usd_in_erc20']]
    return erc20_data


def get_eth_data_zettablock(list_of_addresses, API_key, n_retries=3):
    # ETH transactions obtaining the data
    eth_url = "https://api.zettablock.com/api/v1/dataset/sq_d68db0368d1c41da836e423061af5616/graphql"
    eth_query = """
        query associatedAddresses($address: String!) {
        receiver: records(from_address: $address, limit: 500) {
            data_creation_date
            from_address
            to_address
            sum_value_eth
            max_value_eth
            n_transactions_together
        }
        sender: records(to_address: $address, limit: 500) {
            data_creation_date
            from_address
            to_address
            sum_value_eth
            max_value_eth
            n_transactions_together
        }
        }
    """
    all_eth_transactions = []
    headers = {
            "accept": "application/json",
            "X-API-KEY": API_key,
            "content-type": "application/json"
        }
    for address in list_of_addresses:
        variables = {"address":address}
        payload = {"query": eth_query, "variables": variables}
        for i in range(n_retries):
            try:
                response = requests.post(eth_url, json=payload, headers=headers)
                if response.status_code != 200:
                    raise ValueError(f"Status code: {response.status_code}")
            except Exception as e:
                logger.debug('Retrying')
            else:
                all_eth_transactions.append(pd.DataFrame(response.json()['data']['receiver']))
                all_eth_transactions.append(pd.DataFrame(response.json()['data']['sender']))
                break
        # If the request fails n_retries times, it will skip the address
        if i == (n_retries - 1):
            continue

    all_eth_transactions_df = pd.concat(all_eth_transactions).reset_index(drop=True).drop_duplicates()
    eth_out = all_eth_transactions_df[
        all_eth_transactions_df['from_address'].isin(list_of_addresses)].groupby('from_address').agg(
        {'to_address': 'nunique', 'sum_value_eth': 'sum', 'max_value_eth': 'max', 'n_transactions_together': 'sum'}).reset_index()
    eth_out['avg_value_out_eth'] = eth_out['sum_value_eth'] / eth_out['n_transactions_together']
    eth_out.columns = ['address', 'n_unique_addresses_out', 'total_value_out_eth', 'max_value_out_eth', 'n_transactions_out_eth', 'avg_value_out_eth']

    eth_in = all_eth_transactions_df[
        all_eth_transactions_df['to_address'].isin(list_of_addresses)].groupby('to_address').agg(
        {'from_address': 'nunique', 'sum_value_eth': 'sum', 'max_value_eth': 'max', 'n_transactions_together': 'sum'}).reset_index()
    eth_in['avg_value_in_eth'] = eth_in['sum_value_eth'] / eth_in['n_transactions_together']
    eth_in.columns = ['address', 'n_unique_addresses_in', 'total_value_in_eth', 'max_value_in_eth', 'n_transactions_in_eth', 'avg_value_in_eth']

    all_eth_transactions_temp = all_eth_transactions_df[all_eth_transactions_df['to_address'].isin(list_of_addresses)]
    all_eth_transactions_temp = all_eth_transactions_temp[all_eth_transactions_temp['from_address'].isin(list_of_addresses)]
    all_eth_transactions_temp = all_eth_transactions_temp.groupby(['from_address', 'to_address']).agg(
        {'sum_value_eth': 'sum', 'max_value_eth': 'max', 'n_transactions_together': 'sum'}).reset_index()
    all_eth_transactions_temp['avg_value_together_eth'] = all_eth_transactions_temp['sum_value_eth'] / all_eth_transactions_temp['n_transactions_together']
    all_eth_transactions_temp.columns = ['from_address', 'to_address', 'total_value_together', 'max_value_together_eth', 
                                           'n_transactions_together', 'avg_value_together_eth']    
    
    eth_data = {}
    eth_data['all_eth_transactions'] = all_eth_transactions_temp[[
        'from_address', 'to_address', 'n_transactions_together', 'max_value_together_eth', 'avg_value_together_eth', 
        'total_value_together']]
    eth_data['eth_out'] = eth_out[['address', 'n_transactions_out_eth', 'max_value_out_eth', 'avg_value_out_eth', 'total_value_out_eth']]
    eth_data['eth_in'] = eth_in[['address', 'n_transactions_in_eth', 'max_value_in_eth', 'avg_value_in_eth', 'total_value_in_eth']]
    return eth_data


def prepare_labels(df) -> pd.DataFrame:
    """
    Converts all the label requests from state into a dataframe with the probability of being an attacker/victim 
    of an scam. 
    :param df: pd.DataFrame Dataframe with the label requests
    :return: pd.DataFrame Dataframe with the probability of being an attacker/victim of an scam
    """
    attack_words  = ['phish', 'hack', 'attack', 'Attack', 'scam', 'attacker', 'Attacker', 'scammer-eoa', 'scammer']
    victim_words = ['Victim', 'victim', 'benign']

    labeled = []
    df['entity'] = df['entity'].apply(str.lower)
    for address in df['entity'].unique():
        temp_label = {'address': address, 'attacker': 0, 'victim': 0}
        temp_temp_df = df[df['entity'] == address]
        for i in range(temp_temp_df.shape[0]):
            temp_series = temp_temp_df.iloc[i]
            if any([aw in temp_series['label'] for aw in attack_words]):
                if temp_series['confidence'] > temp_label['attacker']:
                    temp_label['attacker'] = temp_series['confidence']
            elif any([vw in temp_series['label'] for vw in victim_words]):
                if temp_series['confidence'] > temp_label['victim']:
                    temp_label['victim'] = temp_series['confidence']
        labeled.append(temp_label)
    return pd.DataFrame(labeled)


def download_labels_agent(all_nodes_dict, central_node) -> pd.DataFrame:
    t = time.time()
    logger.info(f'{central_node}\tDownloading the automatic labels')
    all_nodes_list = list(all_nodes_dict.keys())
    all_labels = []
    attack_words  = ['phish', 'hack', 'attack', 'Attack', 'scam', 'attacker', 'Attacker', 'scammer-eoa', 'scammer']

    for i in range(int(len(all_nodes_list) / SIMULTANEOUS_ADDRESSES) + 1):
        # This happens if the length of all_nodes_list is a multiple of SIMULTANEOUS_ADDRESSES
        if len(all_nodes_list[(i * SIMULTANEOUS_ADDRESSES):((i + 1) * SIMULTANEOUS_ADDRESSES)]) == 0:
            continue
        query_variables = {
                "state": True,
                "first": 50,
                "sourceIds": attacker_bots,
                "entities": all_nodes_list[(i * SIMULTANEOUS_ADDRESSES):((i + 1) * SIMULTANEOUS_ADDRESSES)],
                "labels": attack_words,
                }
        next_page_exists = True
        # We allow at most n_addresses pages to not overcharge the system, in case there is a contract
        current_page = 0
        while next_page_exists and current_page < SIMULTANEOUS_ADDRESSES:
            response = get_labels(query_variables)
            next_page_exists = response.page_info.has_next_page
            if next_page_exists:
                query_variables['starting_cursor'] = {
                    "page_token": response.page_info.end_cursor.page_token,
                }
            all_labels += response.labels
        query_variables.pop('starting_cursor', None)
        query_variables['sourceIds'] = victim_bots
        query_variables['labels'] = ['Victim', 'victim', 'benign']
        next_page_exists = True
        current_page = 0
        while next_page_exists and current_page < SIMULTANEOUS_ADDRESSES:
            response = get_labels(query_variables)
            next_page_exists = response.page_info.has_next_page
            if next_page_exists:
                query_variables['starting_cursor'] = {
                    "page_token": response.page_info.end_cursor.page_token,
                }
            all_labels += response.labels
    all_labels_df = pd.DataFrame({'entity': [response.entity for response in all_labels],
                                  'label': [response.label for response in all_labels],
                                  'confidence': [response.confidence for response in all_labels],
                                  'entity_type': [response.entity_type for response in all_labels],})
    if all_labels_df.shape[0] == 0:
        raise Warning(f'{central_node}:\tNo labels found, skipping')
    labels_df = prepare_labels(all_labels_df)
    logger.info(f'{central_node}\tDownloaded the automatic labels in {time.time() - t} seconds')
    return labels_df


def get_automatic_labels(all_nodes_dict, transactions_overview, central_node, labels_df,
                         attacker_confidence=0.1, victim_confidence=0.5, victim_sampling=2):
    """
    Gets the automatic labels for the nodes in all_nodes_dict. 
    It uses the labels_df to get the labels of the nodes. The logic to get labels is as follows:
    - If probability of being an attacker is higher than attacker_confidence, it is an attacker
    - If probability of being a victim is higher than victim_confidence, and the probability of being
    an attacker is lower than the minimum between attacker_confidence and victim_confidence, it is a victim
    - In any other case, we don't put any label
    If there are less victims than victing sampling * num_attackers, we add articial victim labels until
    we have victim_sampling * num_attackers victims.
    :param all_nodes_dict: dict Dictionary with the nodes to download the labels from
    :param transactions_overview: pd.DataFrame Dataframe with the transactions
    :param central_node: str Central node
    :param labels_df: pd.DataFrame Dataframe with the labels
    :param attacker_confidence: float Confidence to consider an address as an attacker
    :param victim_confidence: float Confidence to consider an address as a victim
    :param victim_sampling: int Number of victims to add for each attacker
    :return: torch.Tensor tensor with the labels
    :return: dict Dictionary with the labels
    """

    # Start with the process with the labels
    automatic_labels = {address: 'unlabeled' for address in all_nodes_dict.keys()}

    # Attackers
    attackers_list = labels_df.loc[labels_df['attacker']>=attacker_confidence, 'address'].unique().tolist()
    if len(attackers_list) == 0:
        logger.warning(f'{central_node}:\tWith current attacker level {attacker_confidence} there are not enough attackers. Only global model will work')
    if central_node not in attackers_list:
        logger.warning(f'{central_node}:\thas less attacker confidence than {attacker_confidence}')
    num_attackers = len(attackers_list)
    for attacker in attackers_list:
        automatic_labels[attacker] = 'attacker'

    # Victims
    temp_victim = labels_df.loc[labels_df['victim'] >= victim_confidence]
    victims_list = temp_victim.loc[temp_victim['attacker'] < min(victim_confidence, attacker_confidence), 'address'].unique().tolist()
    if len(victims_list) < int(victim_sampling * num_attackers):
        n_victims = int(victim_sampling * num_attackers) - len(victims_list)
        # In case we have to add random victims
        potential_victims = []
        for key in all_nodes_dict.keys():
            if pd.Series(transactions_overview.loc[transactions_overview['from_address'] == key, 'to_address'].values).isin(attackers_list).any():
                if key not in attackers_list and key not in victims_list and key != central_node: # central node is either unlabeled or attacker
                    potential_victims.append(key)
        if len(potential_victims) > n_victims:
            final_victims = np.random.choice(potential_victims, n_victims, replace=False).tolist()
        else:
            logger.debug(f'{central_node}:\t there are not enough unlabeled for adding extra victims')
            final_victims = potential_victims
        final_victims += victims_list
    else:
        final_victims = victims_list.copy()
    for victim in final_victims:
        automatic_labels[victim] = 'victim'

    # Prepare the torch tensor
    labels = torch.ones(len(all_nodes_dict), dtype=torch.long) * -1
    for key in all_nodes_dict.keys():
        if automatic_labels[key] == 'victim':
            labels[all_nodes_dict[key]] = 0
        elif automatic_labels[key] == 'attacker':
            labels[all_nodes_dict[key]] = 1
    return labels, automatic_labels


def put_query_id_dynamo(central_node, query_name, query_id, timeout=4*60*60):
    """
    Puts the query id in dinamoDB. This is used to avoid querying the same address twice.
    """
    itemId = f"scam-label-propagation|queries"
    sortId = f"{central_node}|{query_name}"
    global dynamo
    response = dynamo.put_item(
        Item={"itemId": itemId, 
              "sortKey": sortId, 
              "queryId": query_id, 
              "expiresAt": int(datetime.now().timestamp()) + int(timeout)}
              )
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        logging.error(f"Error putting alert in dynamoDB: {response}")
        return


def get_query_id_dynamo(central_node, query_name):
    """
    Gets the query id in dinamoDB. This is used to avoid querying the same address twice.
    """
    itemId = f"scam-label-propagation|queries"
    sortId = f"{central_node}|{query_name}"
    global dynamo
    response = dynamo.query(KeyConditionExpression='itemId = :id AND sortKey = :sortId',
                            ExpressionAttributeValues={':id': itemId, ':sortId': sortId})
    items = response.get('Items', [])
    if len(items) == 0:
        logger.debug(f"{central_node}:\t{query_name} is not running")
        return None
    else:
        return items[0]['queryId']