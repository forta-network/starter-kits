import logging
import os
import pickle
import numpy as np
import pandas as pd
import torch
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3

from src.constants import (ATTACKER_CONFIDENCE, MIN_FOLDS_ATTACKER, N_FOLDS,
                           PREDICTED_ATTACKER_CONFIDENCE, VICTIM_SAMPLING, SEED, MAX_NEIGHBORS_INDIVIDUAL_MODEL)
from src.model.aux import cross_entropy_masked
from src.model.model import ModelAttention, ModelAttentionMultiHead
from src.model.train import prepare_graph_and_train, prepare_graph_and_predict
from src.preprocessing.get_data import (collect_data_parallel_parts, collect_data_zettablock,
                                        download_labels_graphql,
                                        get_automatic_labels)
from src.preprocessing.process_data import prepare_data

logger = logging.getLogger(__name__)


def run_all(central_node):
    """
    Run the whole pipeline for a given central node. Returns a df with the new addresses classified as attackers
    :param central_node: str with the node to build the graph around and analyze
    :return: pd.DataFrame with the new attackers and the probabilities
    """
    central_node = central_node.lower()
    logger.info(f"{central_node}:\tStart processing")

    # model_type = ModelAttention
    model_type = ModelAttentionMultiHead
    loss_function = cross_entropy_masked

    # data = collect_data_parallel_parts(central_node)
    data = collect_data_zettablock(central_node)
    if not 'production' in os.environ.get('NODE_ENV', ''):
        data_path = 'data3'
        node_path = os.path.join(data_path, f'{central_node}.pkl')
        with open(node_path, 'wb') as f:
            pickle.dump(data, f)
    all_nodes_dict, node_feature, transactions_overview, edge_indexes, edge_features = prepare_data(data)
    labels_df = download_labels_graphql(all_nodes_dict, central_node)
    np.random.seed(SEED)
    web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
    if len(all_nodes_dict) >= MAX_NEIGHBORS_INDIVIDUAL_MODEL:
        logger.info(f"{central_node}:\tToo many neighbors for individual model ({len(all_nodes_dict)}), using only global model")
        filtered_attackers_df = pd.DataFrame(columns=['n_predicted_attacker', 'mean_probs_victim', 'mean_probs_attacker'])
        labels_torch, automatic_labels = get_automatic_labels(
                all_nodes_dict, transactions_overview, central_node, labels_df,
                attacker_confidence=ATTACKER_CONFIDENCE, victim_sampling=VICTIM_SAMPLING)
        original_attackers = [address for address, label in automatic_labels.items() if label == 'attacker']
    else:
        all_results = []
        for _ in range(N_FOLDS):
            labels_torch, automatic_labels = get_automatic_labels(
                all_nodes_dict, transactions_overview, central_node, labels_df,
                attacker_confidence=ATTACKER_CONFIDENCE, victim_sampling=VICTIM_SAMPLING)
            
            model, predictions_every_ten, _ = prepare_graph_and_train(
                node_feature, edge_indexes, edge_features, model_type, loss_function, labels_torch)
            all_results.append({'automatic_labels': automatic_labels, 'model': model,
                                'predictions_every_ten': predictions_every_ten[-1]})
        n_predicted_attacker = torch.sum(torch.stack(
            [torch.argmax(all_results[i]['predictions_every_ten'], axis=1) for i in range(len(all_results))], axis=1), axis=1) # type: ignore
        mean_probs = torch.mean(torch.stack([all_results[i]['predictions_every_ten'] for i in range(len(all_results))]), axis=0) # type: ignore
        all_results_df = pd.DataFrame(
            {'n_predicted_attacker': n_predicted_attacker, 'mean_probs_victim': mean_probs[:, 0], 
            'mean_probs_attacker': mean_probs[:, 1]},
            index=all_results[0]['automatic_labels'].keys())
        all_attackers_df = all_results_df[all_results_df['n_predicted_attacker']>= MIN_FOLDS_ATTACKER]
        original_attackers = [address for address, label in automatic_labels.items() if label == 'attacker']
        # Filtering for the ones that were originally not attackers
        filtered_attackers_df = all_attackers_df.loc[~all_attackers_df.index.isin(original_attackers)]
        # filtering for the average prediction confidence
        filtered_attackers_df = filtered_attackers_df[filtered_attackers_df['mean_probs_attacker'] >= PREDICTED_ATTACKER_CONFIDENCE]
        # Missing checking which of those are contracts
        attackers_not_contracts = []
        for address in list(filtered_attackers_df.index):
            if not is_contract(web3, address):
                attackers_not_contracts.append(address)
        filtered_attackers_df = filtered_attackers_df.loc[attackers_not_contracts]
    # filtered_attackers_df.to_csv(f'results/{central_node}.csv')  # write down for debugging
    logger.debug(filtered_attackers_df)
    logger.info(f"{central_node}:\tFinished processing: {filtered_attackers_df.shape[0]} attackers found")
    graph_statistics = {
        'n_nodes': len(all_nodes_dict),
        'n_labeled_attackers': len(original_attackers),
        'n_predicted_attackers': filtered_attackers_df.shape[0],
        'n_labeled_victims_extended': len([label for label in automatic_labels.values() if label == 'victim']),
        'n_addresses_with_any_label': labels_df.shape[0],
    }
    predictions_global_model = prepare_graph_and_predict(node_feature, edge_indexes, edge_features, labels_torch)
    results_global_model = pd.DataFrame(predictions_global_model.numpy(), index=all_nodes_dict.keys(), columns=['p_victim', 'p_attacker'])
    if results_global_model.loc[central_node].shape[0] == 0:
        logger.info(f"{central_node}:\tThe global model did not predict the central node")
    results_global_model = results_global_model[results_global_model['p_attacker'] >= PREDICTED_ATTACKER_CONFIDENCE]
    results_global_model = results_global_model.loc[~results_global_model.index.isin(original_attackers)]
    attackers_not_contracts_global = []
    for address in list(results_global_model.index):
        if not is_contract(web3, address):
            attackers_not_contracts_global.append(address)
    results_global_model = results_global_model.loc[attackers_not_contracts_global]
    graph_statistics['n_predicted_attackers_global_model'] = results_global_model.shape[0]
    logger.info(f"{central_node}:\tFinished processing: {results_global_model.shape[0]} attackers found with global model")
    return filtered_attackers_df, graph_statistics, results_global_model


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes("0x")
