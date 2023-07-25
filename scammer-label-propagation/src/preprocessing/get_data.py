import time
import torch
import logging
import requests
import numpy as np
import pandas as pd
from datetime import datetime

from src.constants import attacker_bots, victim_bots, SIMULTANEOUS_ADDRESSES, MIN_NEIGHBORS, MAX_NEIGHBORS
from src.storage import get_secrets, dynamo_table


logger = logging.getLogger(__name__)




def collect_data_zettablock(central_node, secrets):
    n_retries = 3
    API_key = secrets['apiKeys']['ZETTABLOCK']
    global dynamo
    dynamo = dynamo_table(secrets)

    list_of_addresses = get_list_of_addresses_zettablock(central_node, API_key, n_retries=n_retries)
    erc20_data = get_erc20_data_zettablock(list_of_addresses, API_key=API_key, n_retries=n_retries)
    eth_data = get_eth_data_zettablock(list_of_addresses, API_key=API_key, n_retries=n_retries)
    data = {**erc20_data, **eth_data}
    logger.info(f'{central_node}:\tData collected')
    return data


def get_list_of_addresses_zettablock(central_node, API_key, n_retries=3):
    # Fist step is to query all the addresses that had some interaction with the central node
    all_addresses_url = "https://api.zettablock.com/api/v1/dataset/sq_4afc4b8183174d1dbbef855a0144efd4/graphql"  # 1 year
    # all_addresses_url = "https://api.zettablock.com/api/v1/dataset/sq_bb1d414ac0ac4d76a1ff1ae2e2b5c3f0/graphql"  # 6 months
    # all_addresses_url = "https://api.zettablock.com/api/v1/dataset/sq_1e1871c668514f47900937484d974d68/graphql"  # new 6 months
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
        raise Warning(f'{central_node}:\tNot enough neighbors, skipping')
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


def get_all_related_addresses(central_node) -> str:
    """
    Querying allium. Returns the list of addresses that are first order neighbours of the central node.
    :param central_node: str Address that will be the center of the graph
    :return: str All addresses that are first order neighbours of the central node comma separated in a string
    """
    # The SQL query for this can be found in file src/preprocessing/queries.sql
    logger.info(f'{central_node}\tQuerying all related addresses')
    API_key = get_secrets()['apiKeys']['ALLIUM']
    query_name = 'get_addresses'
    run_id = get_query_id_dynamo(central_node, query_name)
    logger.debug(f'{central_node}:\t{query_name}:\t{run_id}')
    api_url = f'https://api.allium.so/api/v1/explorer/queries/Q71VcKtUFjBtloXNZtpD/run-async'
    max_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if run_id is None:
        # Retry mechanism in case the request fails
        for i in range(5):
            try:
                response = requests.post(
                    api_url,
                    json={"parameters" :{"address":central_node, "tt": max_datetime}},
                    headers={"X-API-Key": API_key},
                )
                run_id = response.json()["run_id"]
            except Exception as e:
                logger.debug(f'Retrying for {i+1} time')
                if i == 4:
                    raise ValueError(f'{central_node}:\t{query_name} query failed. {response}.\n{e}', exc_info=True)
            else:
                break
        put_query_id_dynamo(central_node, query_name, run_id)
    continue_querying = True
    max_number_of_retries = 50  # 50 * 20 seconds = 1000 seconds = 16 minutes max time running
    n_retry = 0
    while continue_querying:
        # Retry mechanism in case the request fails
        for i in range(5):
            try:
                response = requests.get(
                    f"https://api.allium.so/api/v1/explorer/query-runs/{run_id}/status",
                    headers={"X-API-Key": API_key},
                    timeout=20,
                )
                run_status = response.json()
            except Exception as e:
                logger.debug(f'Retrying for {i+1} time')
                if i == 4:
                    raise ValueError(f'{central_node}:\tGet addresses query failed. {response}.\n{e}', exc_info=True)
            else:
                break
        logger.info(f"{central_node}:\t{query_name} query still {run_status} with id {run_id}")
        if run_status in ['failed', 'canceled']:
            logger.debug(f"{central_node}:\t{query_name} query failed. Re-querying. {response.json()}")
            # Retry mechanism in case the request fails
            for i in range(5):
                try:
                    response = requests.post(
                        api_url,
                        json={"parameters" :{"address":central_node, "tt": max_datetime}},
                        headers={"X-API-Key": API_key},
                    )
                    run_id = response.json()["run_id"]
                except Exception as e:
                    logger.debug(f'Retrying for {i+1} time')
                    if i == 4:
                        raise ValueError(f'{central_node}:\t{query_name} query failed. {response}.\n{e}', exc_info=True)
                else:
                    break
            put_query_id_dynamo(central_node, query_name, run_id)
        elif run_status == 'success':
            # Query is finished, we download the data. Retry more times to reduce costs.
            for i in range(5):
                try:
                    response = requests.get(
                        f"https://api.allium.so/api/v1/explorer/query-runs/{run_id}/results?f=json",
                        headers={"X-API-Key": API_key},
                    )
                    _ = response.json()  # Try to parse the response. If answer is not 200, it will retry the request
                    continue_querying = False
                except Exception as e:
                    logger.debug(f'Retrying for {i+1} time')
                    if i == 4:
                        raise ValueError(f'{central_node}:\t{query_name} query failed. {response}.\n{e}', exc_info=True)
                else:
                    break
        n_retry += 1
        if n_retry > max_number_of_retries:
            raise Warning(f'{central_node}:\t{query_name} query took too long, skipping')
        if continue_querying:
            logger.debug(f"{central_node}:\t{query_name} query still running")
            time.sleep(20)
    if 'data' not in response.json().keys():
        raise ValueError(f'{central_node}:\tMore than 3 errors querying list of neighbors, skipping')
    if len(response.json()['data']) < MIN_NEIGHBORS:
        raise Warning(f'{central_node}:\tNot enough neighbors, skipping')
    if len(response.json()['data']) > MAX_NEIGHBORS:
        raise Warning(f'{central_node}:\tToo many neighbors, skipping')
    list_of_addresses = str(tuple(pd.DataFrame(response.json()['data'])['address'].tolist()))
    return list_of_addresses


def collect_data_parallel_parts(central_node) -> pd.DataFrame:
    """
    Querying allium. Based on the central node, obtains all the addresses that are first order neighbors, 
    and then queries allium for the transactions of those addresses. Transactions are divided into 6 categories:
    - all_eth_transactions: all transactions that involve ETH
    - all_erc20_transactions: all transactions that involve ERC20 tokens
    - eth_out: all transactions that involve ETH and are outgoing
    - eth_in: all transactions that involve ETH and are incoming
    - erc20_out: all transactions that involve ERC20 tokens and are outgoing
    - erc20_in: all transactions that involve ERC20 tokens and are incoming
    :param central_node: str Address that will be the center of the graph
    :return: dict Dictionary with the 6 categories of transactions
    """
    waiting_time = 30
    API_key = get_secrets()['apiKeys']['ALLIUM']
    max_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    list_of_addresses = get_all_related_addresses(central_node)
    # The SQL query for this can be found in file src/preprocessing/queries.sql
    queries = {
        'all_eth_transactions': 'yteFwmN3zZbQLoc9bY9g',
        'all_erc20_transactions': 'YgEXG57MAP1VMZMxTXDe',
        'eth_out': 'SBgNG6VWYcTXMlG9s3Ar',
        'eth_in': 'hLnejllWt6nfij115dLA',
        'erc20_out': 'C0O5JAZPY4YIs5yJCiUE',
        'erc20_in': 'i61RQqEcLRLidt9qAIrg'
    }
    active_queries = {}
    total_retries = 0
    max_retries = 10
    data = {}
    logger.info(f'{central_node}:\tDownloading the data')
    for key in queries.keys():
        logger.debug(f'{central_node}:\t{key}')
        api_url = f'https://api.allium.so/api/v1/explorer/queries/{queries[key]}/run-async'
        run_id = get_query_id_dynamo(central_node, key)
        logger.debug(f'{central_node}:\t{key}:\t{run_id}')
        if run_id is None:
            # Retry mechanism in case the request fails
            for i in range(5):
                try:
                    response = requests.post(
                        api_url,
                        json={"parameters" :{"addresses":list_of_addresses,"tt":max_datetime}},
                        headers={"X-API-Key": API_key},
                    )
                    active_queries[key] = response.json()["run_id"]
                except Exception as e:
                    logger.debug(f'Retrying for {i+1} time')
                    if i == 4:
                        raise ValueError(f'{central_node}:\t{key} query failed. {response}.\n{e}', exc_info=True)
                else:
                    break
            put_query_id_dynamo(central_node, key, active_queries[key])
        else:
            active_queries[key] = run_id
    while len(active_queries) > 0 and total_retries < max_retries:
        keys_to_pop = []
        logger_str = f'{central_node}:\t'
        for key in active_queries.keys():
            # Retry mechanism in case the request fails
            for i in range(5):
                try:
                    response = requests.get(
                        f"https://api.allium.so/api/v1/explorer/query-runs/{active_queries[key]}/status",
                        headers={"X-API-Key": API_key},
                        timeout=10,
                    )
                    run_status = response.json()
                except Exception as e:
                    logger.debug(f'Retrying for {i+1} time')
                    if i == 4:
                        raise ValueError(f'{central_node}:\t{key} query failed. {response}.\n{e}', exc_info=True)
                else:
                    break
            # logger.info(f'{central_node}:\t{key}\t{active_queries[key]}\t{run_status}')
            logger_str += f'{key}:\t{active_queries[key]}-{run_status}\t'
            if run_status in ['failed', 'canceled']:
                logger.debug(f"{central_node}:\t{key} query failed. Re-querying. {response.json()}")
                api_url = f'https://api.allium.so/api/v1/explorer/queries/{queries[key]}/run-async'
                # Retry mechanism in case the request fails
                for i in range(5):
                    try:
                        response = requests.post(
                            api_url,
                            json={"parameters" :{"addresses":list_of_addresses,"tt":max_datetime}},
                            headers={"X-API-Key": API_key},
                        )
                        active_queries[key] = response.json()["run_id"]
                        total_retries += 1
                    except Exception as e:
                        logger.debug(f'Retrying for {i+1} time')
                        if i == 4:
                            raise ValueError(f'{central_node}:\t{key} query failed. {response}.\n{e}', exc_info=True)
                    else:
                        break
                put_query_id_dynamo(central_node, key, active_queries[key])
            elif run_status == 'success':
                # Query is finished, we download the data. Retry more times to reduce costs.
                for i in range(5):
                    try:
                        response = requests.get(
                            f"https://api.allium.so/api/v1/explorer/query-runs/{active_queries[key]}/results?f=json",
                            headers={"X-API-Key": API_key},
                        )
                        data[key] = pd.DataFrame(response.json()['data'])
                        keys_to_pop.append(key)
                        logger.debug(f"{central_node}:\t{key} Finished")
                    except Exception as e:
                        logger.debug(f'Retrying for {i+1} time')
                        if i == 4:
                            raise ValueError(f'{central_node}:\t{key} query failed. {response}.\n{e}', exc_info=True)
                    else:
                        break
        for key in keys_to_pop:
            active_queries.pop(key)
        logger.info(logger_str)
        if len(active_queries) > 0:
            logger.debug(f"{central_node}:\t{len(active_queries)} queries still running")
            time.sleep(waiting_time)
    logger.info(f'{central_node}:\tFinished downloading the data')
    return data


def prepare_labels(df) -> pd.DataFrame:
    """
    Converts all the label requests from state into a dataframe with the probability of being an attacker/victim 
    of an scam. 
    :param df: pd.DataFrame Dataframe with the label requests
    :return: pd.DataFrame Dataframe with the probability of being an attacker/victim of an scam
    """
    attack_words  = ['phish', 'hack', 'attack', 'Attack', 'scam']
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


def download_labels_graphql(all_nodes_dict, central_node) -> pd.DataFrame:
    """
    Downloads the labels of the nodes in all_nodes_dict. It uses the graphql API of Forta.
    :param all_nodes_dict: dict Dictionary with the nodes to download the labels from
    :param central_node: str Central node
    :return: pd.DataFrame Dataframe with the labels"""
    logger.info(f'{central_node}\tDownloading the automatic labels')
    forta_api = "https://api.forta.network/graphql"
    headers = {"content-type": "application/json"}
    query = """
    query Query($labelsInput: LabelsInput) {
    labels(input: $labelsInput) {
        labels {
        label {
            label
            entity
            confidence
        }
        source {
            bot {
            id
            }
        }
        }
    pageInfo {
        endCursor {
            pageToken
        }
        hasNextPage
        }
    }
    }
    """
    all_nodes_list = list(all_nodes_dict.keys())
    all_labels = []
    for i in range(int(len(all_nodes_list) / SIMULTANEOUS_ADDRESSES) + 1):
        # This happens if the length of all_nodes_list is a multiple of SIMULTANEOUS_ADDRESSES
        if len(all_nodes_list[(i * SIMULTANEOUS_ADDRESSES):((i + 1) * SIMULTANEOUS_ADDRESSES)]) == 0:
            continue
        # We query first the potential attackers.
        query_variables = {
            "labelsInput": {
                "state": True,
                "first": 50,
                "sourceIds": attacker_bots,
                "entities": all_nodes_list[(i * SIMULTANEOUS_ADDRESSES):((i + 1) * SIMULTANEOUS_ADDRESSES)]
                }
            }
        next_page_exists = True
        # We allow at most n_addresses pages to not overcharge the system, in case there is a contract
        current_page = 0
        while next_page_exists and current_page < SIMULTANEOUS_ADDRESSES:
            for i in range(5):
                try:
                    payload = dict(query=query, variables=query_variables)
                    response = requests.request("POST", forta_api, json=payload, headers=headers)
                    all_labels += response.json()['data']['labels']['labels']
                except Exception as e:
                    logger.debug(f'Retrying for {i+1} time')
                    if i == 4:
                        raise ValueError(f'{central_node}:\tLabels query failed. {response}.\n{e}', exc_info=True)
                else:
                    break
            next_page_exists = response.json()['data']['labels']['pageInfo']['hasNextPage']
            query_variables['labelsInput']['after'] = response.json()['data']['labels']['pageInfo']['endCursor']
            current_page += 1
        # Now query victims
        query_variables = {
            "labelsInput": {
                "state": True,
                "first": 50,
                "sourceIds": victim_bots,
                "labels": ['Victim', 'victim', 'benign'],
                "entities": all_nodes_list[(i * SIMULTANEOUS_ADDRESSES):((i + 1) * SIMULTANEOUS_ADDRESSES)]
                }
            }
        next_page_exists = True
        # We allow at most n_addresses pages to not overcharge the system, in case there is a contract
        current_page = 0
        while next_page_exists and current_page < SIMULTANEOUS_ADDRESSES:
            for i in range(5):
                try:
                    payload = dict(query=query, variables=query_variables)
                    response = requests.request("POST", forta_api, json=payload, headers=headers)
                    all_labels += response.json()['data']['labels']['labels']
                except Exception as e:
                    logger.debug(f'Retrying for {i+1} time')
                    if i == 4:
                        raise ValueError(f'{central_node}:\tLabels query failed. {response}.\n{e}', exc_info=True)
                else:
                    break
            next_page_exists = response.json()['data']['labels']['pageInfo']['hasNextPage']
            end_cursor = response.json()['data']['labels']['pageInfo']['endCursor']
            query_variables['labelsInput']['after'] = end_cursor
            current_page += 1
    all_labels_df = pd.DataFrame([response['label'] for response in all_labels])
    if all_labels_df.shape[0] == 0:
        raise Warning(f'{central_node}:\tNo labels found, skipping')
    labels_df = prepare_labels(all_labels_df)
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