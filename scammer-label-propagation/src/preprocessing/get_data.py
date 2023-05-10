import time
import torch
import logging
import requests
import numpy as np
import pandas as pd
from datetime import datetime

from src.constants import attacker_bots, victim_bots, SIMULTANEOUS_ADDRESSES, MIN_NEIGHBORS
from src.storage import get_secrets

logger = logging.getLogger(__name__)


def get_all_related_addresses(central_node) -> str:
    """
    Querying allium. Returns the list of addresses that are first order neighbours of the central node.
    :param central_node: str Address that will be the center of the graph
    :return: str All addresses that are first order neighbours of the central node comma separated in a string
    """
    logger.info(f'{central_node}\tQuerying all related addresses')
    API_key = get_secrets()['jsonRpc']['ALLIUM']
    api_url = f'https://api.allium.so/api/v1/explorer/queries/Q71VcKtUFjBtloXNZtpD/run'
    max_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for i in range(3):
        try:
            response = requests.post(
                api_url,
                json={"address":central_node,"tt":max_datetime},
                headers={"X-API-Key": API_key},
            )
        except Exception as e:
            logger.debug(f'Retrying for {i+1} time')
        else:
            break
    if 'data' not in response.json().keys():
        raise ValueError(f'{central_node}:\tMore than 3 errors querying list of neighbors, skipping')
    if len(response.json()['data']) < MIN_NEIGHBORS:
        raise ValueError(f'{central_node}:\tNot enough neighbors, skipping')
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
    API_key = get_secrets()['jsonRpc']['ALLIUM']
    max_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    list_of_addresses = get_all_related_addresses(central_node)  
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
    logger.debug(f'{central_node}:\tDownloading the data')
    for key in queries.keys():
        logger.debug(f'{central_node}:\t{key}')
        api_url = f'https://api.allium.so/api/v1/explorer/queries/{queries[key]}/run-async'
        response = requests.post(
            api_url,
            json={"parameters" :{"addresses":list_of_addresses,"tt":max_datetime}},
            headers={"X-API-Key": API_key},
        )
        active_queries[key] = response.json()["run_id"]
    
    while len(active_queries) > 0 and total_retries < max_retries:
        keys_to_pop = []
        for key in active_queries.keys():
            response = requests.get(
                f"https://api.allium.so/api/v1/explorer/query-runs/{active_queries[key]}/status",
                headers={"X-API-Key": API_key},
                timeout=10,
            )
            run_status = response.json()
            if run_status == 'failed':
                logger.debug(f"{central_node}:\t{key} query failed. Re-querying. {response.json()}")
                api_url = f'https://api.allium.so/api/v1/explorer/queries/{queries[key]}/run-async'
                response = requests.post(
                    api_url,
                    json={"parameters" :{"addresses":list_of_addresses,"tt":max_datetime}},
                    headers={"X-API-Key": API_key},
                )
                active_queries[key] = response.json()["run_id"]
                total_retries += 1
            elif run_status == 'success':
                try:
                    response = requests.get(
                        f"https://api.allium.so/api/v1/explorer/query-runs/{active_queries[key]}/results?f=json",
                        headers={"X-API-Key": API_key},
                    )
                    data[key] = pd.DataFrame(response.json()['data'])
                    keys_to_pop.append(key)
                    # active_queries.pop(key)
                    logger.debug(f"{central_node}:\t{key} Finished")
                except Exception as e:
                    logger.error(e)
                    logger.debug(f"{central_node}:\t{key} failed after successfully running the query. Re-querying")
                    api_url = f'https://api.allium.so/api/v1/explorer/queries/{queries[key]}/run-async'
                    response = requests.post(
                        api_url,
                        json={"parameters" :{"addresses":list_of_addresses,"tt":max_datetime}},
                        headers={"X-API-Key": API_key},
                    )
                    active_queries[key] = response.json()["run_id"]
                    total_retries += 1
        for key in keys_to_pop:
            active_queries.pop(key)
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
            for i in range(3):
                try:
                    payload = dict(query=query, variables=query_variables)
                    response = requests.request("POST", forta_api, json=payload, headers=headers)
                    all_labels += response.json()['data']['labels']['labels']
                except Exception as e:
                        logger.debug(f'Retrying for {i+1} time')
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
            for i in range(3):
                try:
                    payload = dict(query=query, variables=query_variables)
                    response = requests.request("POST", forta_api, json=payload, headers=headers)
                    all_labels += response.json()['data']['labels']['labels']
                except Exception as e:
                        logger.debug(f'Retrying for {i+1} time')
                else:
                    break
            next_page_exists = response.json()['data']['labels']['pageInfo']['hasNextPage']
            end_cursor = response.json()['data']['labels']['pageInfo']['endCursor']
            query_variables['labelsInput']['after'] = end_cursor
            current_page += 1
    all_labels_df = pd.DataFrame([response['label'] for response in all_labels])
    if all_labels_df.shape[0] == 0:
        raise ValueError(f'{central_node}:\tNo labels found, skipping')
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
        raise ValueError(f'{central_node}:\tWith current attacker level {attacker_confidence} there are not enough attackers. Go to next address')
    if central_node not in attackers_list:
        raise ValueError(f'{central_node}:\thas less attacker confidence than {attacker_confidence}. Go to next address')
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
