import logging

import numpy as np
import pandas as pd
import requests
import torch
from sklearn.preprocessing import StandardScaler
from torch_geometric.data import HeteroData

from constants import ZETTABLOCK_FP_MITIGATION_URL


class DownloadData:
    def __init__(self, secrets) -> None:
        self.headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "X-API-KEY": secrets['apiKeys']['ZETTABLOCK']
        }
        self.data_url = ZETTABLOCK_FP_MITIGATION_URL
        
    def get_initial_data(self, central_node):
        from_query = """
        query getFromCenter($central_address: String!){
        data: records(from_address: $central_address)
        {
            from_address
            to_address
            tx_from
            tx_to
            sum_eth_transfer_eth
            max_eth_transfer_eth
            n_transactions_eth
            n_different_blocks_eth
            block_range_eth
            avg_gas_price_gwei_eth
            range_gas_price_gwei_eth
            n_transactions_erc721
            n_unique_transactions_erc721
            n_unique_tokens_erc721
            avg_token_tx_erc721
            max_token_tx_erc721
            avg_value_erc721
            max_value_erc721
            n_different_blocks_erc721
            block_range_erc721
            avg_gas_price_gwei_erc721
            range_gas_price_gwei_erc721
            sum_usd_price_erc20
            max_usd_price_erc20
            n_transactions_erc20
            n_different_blocks_erc20
            n_tokens_erc20
            n_different_contracts_erc20
            block_range_erc20
            avg_gas_price_gwei_erc20
            range_gas_price_gwei_erc20
        }
        }
        """
        to_query = """
        query getFromCenter($central_address: String!){
        data: records(to_address: $central_address)
        {
            from_address
            to_address
            tx_from
            tx_to
            sum_eth_transfer_eth
            max_eth_transfer_eth
            n_transactions_eth
            n_different_blocks_eth
            block_range_eth
            avg_gas_price_gwei_eth
            range_gas_price_gwei_eth
            n_transactions_erc721
            n_unique_transactions_erc721
            n_unique_tokens_erc721
            avg_token_tx_erc721
            max_token_tx_erc721
            avg_value_erc721
            max_value_erc721
            n_different_blocks_erc721
            block_range_erc721
            avg_gas_price_gwei_erc721
            range_gas_price_gwei_erc721
            sum_usd_price_erc20
            max_usd_price_erc20
            n_transactions_erc20
            n_different_blocks_erc20
            n_tokens_erc20
            n_different_contracts_erc20
            block_range_erc20
            avg_gas_price_gwei_erc20
            range_gas_price_gwei_erc20
        }
        }
        """
        tx_from_query = """
        query getFromCenter($central_address: String!){
        data: records(tx_from: $central_address)
        {
            from_address
            to_address
            tx_from
            tx_to
            sum_eth_transfer_eth
            max_eth_transfer_eth
            n_transactions_eth
            n_different_blocks_eth
            block_range_eth
            avg_gas_price_gwei_eth
            range_gas_price_gwei_eth
            n_transactions_erc721
            n_unique_transactions_erc721
            n_unique_tokens_erc721
            avg_token_tx_erc721
            max_token_tx_erc721
            avg_value_erc721
            max_value_erc721
            n_different_blocks_erc721
            block_range_erc721
            avg_gas_price_gwei_erc721
            range_gas_price_gwei_erc721
            sum_usd_price_erc20
            max_usd_price_erc20
            n_transactions_erc20
            n_different_blocks_erc20
            n_tokens_erc20
            n_different_contracts_erc20
            block_range_erc20
            avg_gas_price_gwei_erc20
            range_gas_price_gwei_erc20
        }
        }
        """
        tx_to_query = """
        query getFromCenter($central_address: String!){
        data: records(tx_to: $central_address)
        {
            from_address
            to_address
            tx_from
            tx_to
            sum_eth_transfer_eth
            max_eth_transfer_eth
            n_transactions_eth
            n_different_blocks_eth
            block_range_eth
            avg_gas_price_gwei_eth
            range_gas_price_gwei_eth
            n_transactions_erc721
            n_unique_transactions_erc721
            n_unique_tokens_erc721
            avg_token_tx_erc721
            max_token_tx_erc721
            avg_value_erc721
            max_value_erc721
            n_different_blocks_erc721
            block_range_erc721
            avg_gas_price_gwei_erc721
            range_gas_price_gwei_erc721
            sum_usd_price_erc20
            max_usd_price_erc20
            n_transactions_erc20
            n_different_blocks_erc20
            n_tokens_erc20
            n_different_contracts_erc20
            block_range_erc20
            avg_gas_price_gwei_erc20
            range_gas_price_gwei_erc20
        }
        }
        """
        variables = {'central_address': central_node}
        payload_from = {'query': from_query, 'variables': variables}
        payload_to = {'query': to_query, 'variables': variables}
        payload_tx_from = {'query': tx_from_query, 'variables': variables}
        payload_tx_to = {'query': tx_to_query, 'variables': variables}

        response_from = requests.post(self.data_url, json=payload_from, headers=self.headers)
        response_to = requests.post(self.data_url, json=payload_to, headers=self.headers)
        response_tx_from = requests.post(self.data_url, json=payload_tx_from, headers=self.headers)
        response_tx_to = requests.post(self.data_url, json=payload_tx_to, headers=self.headers)

        all_data = pd.concat([
            pd.DataFrame(response_from.json()['data']['data']),
            pd.DataFrame(response_to.json()['data']['data']),
            pd.DataFrame(response_tx_from.json()['data']['data']),
            pd.DataFrame(response_tx_to.json()['data']['data'])
        ])
        return all_data

    def get_data_zettablock(self, central_node):
        column_order = ['from_address', 'to_address', 'tx_from', 'tx_to',
        'sum_eth_transfer_eth', 'max_eth_transfer_eth', 'n_transactions_eth',
        'n_different_blocks_eth', 'block_range_eth', 'avg_gas_price_gwei_eth',
        'range_gas_price_gwei_eth', 'sum_usd_price_erc20',
        'max_usd_price_erc20', 'n_transactions_erc20',
        'n_different_blocks_erc20', 'n_tokens_erc20',
        'n_different_contracts_erc20', 'block_range_erc20',
        'avg_gas_price_gwei_erc20', 'range_gas_price_gwei_erc20',
        'n_transactions_erc721', 'n_unique_transactions_erc721',
        'n_unique_tokens_erc721', 'avg_token_tx_erc721', 'max_token_tx_erc721',
        'avg_value_erc721', 'max_value_erc721', 'n_different_blocks_erc721',
        'block_range_erc721', 'avg_gas_price_gwei_erc721',
        'range_gas_price_gwei_erc721']
        data = self.get_initial_data(central_node)
        data = data[column_order]
        data = data.drop_duplicates()
        return data
    
    def create_graph_around_address(self, central_node, total_addresses=500):
        try:
            np.seterr(invalid='ignore')

            data_central_node = self.get_data_zettablock(central_node)
            
            addresses_columns = ['from_address', 'to_address', 'tx_from', 'tx_to']
            column_aggregations = {
                'sum_eth_transfer_eth': ['sum', 'mean', 'std'],
                'max_eth_transfer_eth': ['mean', 'std', 'max'],
                'n_transactions_eth': ['sum', 'mean', 'std', 'count'],
                'n_different_blocks_eth': ['sum', 'mean', 'std'],
                'block_range_eth': ['mean', 'std'],
                'avg_gas_price_gwei_eth': ['mean', 'std', 'max'],
                'range_gas_price_gwei_eth': ['mean', 'std', 'max', 'min'],
                'sum_usd_price_erc20': ['sum', 'mean', 'std'],
                'max_usd_price_erc20': ['mean', 'std', 'max'],
                'n_transactions_erc20': ['sum', 'mean', 'std'],
                'n_different_blocks_erc20': ['sum', 'mean', 'std'],
                'block_range_erc20': ['mean', 'std'],
                'n_tokens_erc20': ['sum', 'mean', 'std'],
                'n_different_contracts_erc20': ['sum', 'mean', 'std'],
                'avg_gas_price_gwei_erc20': ['mean', 'std', 'max'],
                'range_gas_price_gwei_erc20': ['mean', 'std', 'max', 'min'],
                'n_transactions_erc721': ['sum', 'mean', 'std'],
                'n_unique_transactions_erc721': ['sum', 'mean', 'std'],
                'n_unique_tokens_erc721': ['sum', 'mean', 'std'],
                'avg_token_tx_erc721': ['mean', 'std'],
                'max_token_tx_erc721': ['mean', 'std', 'max'],
                'avg_value_erc721': ['mean', 'std', 'max'],
                'max_value_erc721': ['mean', 'std', 'max'],
                'n_different_blocks_erc721': ['sum', 'mean', 'std'],
                'block_range_erc721': ['mean', 'std'],
                'avg_gas_price_gwei_erc721': ['mean', 'std', 'max'],
                'range_gas_price_gwei_erc721': ['mean', 'std', 'max', 'min'],
            }
            # Get all the addresses that had interactions

            unique_addresses = np.unique(data_central_node[addresses_columns].values)
            if len(unique_addresses) > total_addresses:
                return None
            # Get the address info
            aggregations_dict = {'from_address': 'out', 'to_address': 'in', 'tx_from': 'tx_out', 'tx_to': 'tx_in'}
            all_aggregations = []
            for key, item in aggregations_dict.items():
                temp = data_central_node[data_central_node[key].isin(unique_addresses)]
                temp.loc[:, ~temp.columns.isin(addresses_columns)] = temp.loc[:, ~temp.columns.isin(addresses_columns)].apply(pd.to_numeric)

                temp_aggregation = {**{column: 'nunique' for column in addresses_columns if column != key}, **column_aggregations}
                # temp_aggregation = {column: 'nunique' for column in addresses_columns if column != key} | column_aggregations
                temp = temp.groupby(key).agg(temp_aggregation)
                temp.columns = [f'{item}_{col[0]}_{col[1]}' for col in temp.columns]
                temp.index.name = 'address'
                all_aggregations.append(temp)
            address_info = pd.concat(all_aggregations, axis=1)

            # Get the transactions
            temp = data_central_node.copy().drop_duplicates()
            temp_aggregation = {**{'from_address': 'nunique', 'to_address': 'nunique'}, **column_aggregations}
            # temp_aggregation = {'from_address': 'nunique', 'to_address': 'nunique'} | column_aggregations
            transactions_info = temp.groupby(['from_address', 'to_address']).agg(temp_aggregation)
            transactions_info.columns = [f'{col[0]}_{col[1]}' for col in transactions_info.columns]

            # txfrom 
            temp_aggregation = {**{'from_address': 'nunique', 'to_address': 'nunique', 'tx_from': 'nunique'}, **column_aggregations}
            # temp_aggregation = {'from_address': 'nunique', 'to_address': 'nunique', 'tx_from': 'nunique'} | column_aggregations
            txfrom_info = temp.groupby(['from_address', 'to_address', 'tx_from']).agg(temp_aggregation)
            txfrom_info.columns = [f'{col[0]}_{col[1]}' for col in txfrom_info.columns]

            # txto
            temp_aggregation = {**{'from_address': 'nunique', 'to_address': 'nunique', 'tx_to': 'nunique'}, **column_aggregations}
            # temp_aggregation = {'from_address': 'nunique', 'to_address': 'nunique', 'tx_to': 'nunique'} | column_aggregations
            txto_info = temp.groupby(['from_address', 'to_address', 'tx_to']).agg(temp_aggregation)
            txto_info.columns = [f'{col[0]}_{col[1]}' for col in txto_info.columns]

            # Indexes
            addresses_indexes = {ad: val for val, ad in enumerate(address_info.index.values)}
            transactions_indexes = {ad: val for val, ad in enumerate(transactions_info.index.values)}
            address_to_tx_idx = [[add_value, tx_value] for tx_key, tx_value in transactions_indexes.items() for add_key, add_value in addresses_indexes.items() if tx_key[0] == add_key]

            tx_to_address_idx = [[tx_value, add_value] for tx_key, tx_value in transactions_indexes.items() for add_key, add_value in addresses_indexes.items() if tx_key[1] == add_key]

            address_starts_transaction_small = txfrom_info.reset_index()
            transaction_ends_address_small = txto_info.reset_index()
            address_starts_transaction_idx = [[addresses_indexes[address_starts_transaction_small['tx_from'].iloc[i]],
                                            transactions_indexes[(address_starts_transaction_small['from_address'].iloc[i], 
                                            address_starts_transaction_small['to_address'].iloc[i])]] for i in range(address_starts_transaction_small.shape[0])]
            transaction_ends_address_idx = [[transactions_indexes[(transaction_ends_address_small['from_address'].iloc[i], transaction_ends_address_small['to_address'].iloc[i])],
                                            addresses_indexes[transaction_ends_address_small['tx_to'].iloc[i]]] for i in range(transaction_ends_address_small.shape[0])]

            # HeteroData no scaling
            data = HeteroData()
            data['address'].x = torch.Tensor(address_info.values.astype(np.float32))
            data['transaction'].x = torch.Tensor(transactions_info.values.astype(np.float32))

            data['address', 'sends', 'transaction'].edge_index = torch.tensor(address_to_tx_idx, dtype=torch.long).t()
            data['transaction', 'receives', 'address'].edge_index = torch.tensor(tx_to_address_idx, dtype=torch.long).t()
            data['address', 'starts', 'transaction'].edge_index = torch.tensor(address_starts_transaction_idx, dtype=torch.long).t()
            data['transaction', 'ends', 'address'].edge_index = torch.tensor(transaction_ends_address_idx, dtype=torch.long).t()

            data['address', 'starts', 'transaction'].edge_attr = torch.tensor(
                address_starts_transaction_small.drop(columns=['from_address', 'to_address', 'tx_from']).values.astype(np.float32), dtype=torch.float)
            data['transaction', 'ends', 'address'].edge_attr = torch.tensor(
                transaction_ends_address_small.drop(columns=['from_address', 'to_address', 'tx_to']).values.astype(np.float32), dtype=torch.float)

            # Hetero data with scaling
            normalized_data = HeteroData()
            normalized_data['address'].x = torch.Tensor(np.nan_to_num(StandardScaler().fit_transform(address_info.values.astype(np.float32))))
            normalized_data['transaction'].x = torch.Tensor(np.nan_to_num(StandardScaler().fit_transform(transactions_info.values.astype(np.float32))))

            normalized_data['address', 'sends', 'transaction'].edge_index = torch.tensor(address_to_tx_idx, dtype=torch.long).t()
            normalized_data['transaction', 'receives', 'address'].edge_index = torch.tensor(tx_to_address_idx, dtype=torch.long).t()
            normalized_data['address', 'starts', 'transaction'].edge_index = torch.tensor(address_starts_transaction_idx, dtype=torch.long).t()
            normalized_data['transaction', 'ends', 'address'].edge_index = torch.tensor(transaction_ends_address_idx, dtype=torch.long).t()

            normalized_data['address', 'starts', 'transaction'].edge_attr = torch.tensor(
                StandardScaler().fit_transform(np.nan_to_num(address_starts_transaction_small.drop(columns=['from_address', 'to_address', 'tx_from']).values.astype(np.float32))), 
                dtype=torch.float)
            normalized_data['transaction', 'ends', 'address'].edge_attr = torch.tensor(
                StandardScaler().fit_transform(np.nan_to_num(transaction_ends_address_small.drop(columns=['from_address', 'to_address', 'tx_to']).values.astype(np.float32))),
                dtype=torch.float)

            graph = {
                'graph': data,
                'normalized_graph': normalized_data,
                'address_indexes': addresses_indexes,
                'transaction_indexes': transactions_indexes,
                'address': central_node,
                'index_central_address': addresses_indexes[central_node],
                'unique_tx_from': np.unique(data_central_node['tx_from'].values)
            }
            return graph
        except RuntimeWarning as rtw:
            logging.info(f'fpfp-error-{rtw}')
            return None
        except Exception as e:
            logging.info(f'fpfp-error-{e}')
            return None
