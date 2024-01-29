import logging

import numpy as np
import pandas as pd
import requests
import torch
import json
import time
from sklearn.preprocessing import StandardScaler
from torch_geometric.data import HeteroData
from concurrent.futures import ThreadPoolExecutor

from src.constants import ZETTABLOCK_FP_MITIGATION_URL


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
        
        all_payloads = [payload_from, payload_to, payload_tx_from, payload_tx_to]
        timeout = 10
        tp = ThreadPoolExecutor(max_workers=4)
        post_results = [tp.submit(self.aux_post, self.data_url, payload, self.headers, timeout) for payload in all_payloads]
        tp.shutdown(wait=True)

        all_results_data = [res.result().json()['data']['data'] for res in post_results]
        all_data = pd.concat([pd.DataFrame(data) for data in all_results_data])
        return all_data

    @staticmethod
    def aux_post(url, payload, headers, timeout=10):
        return requests.post(url, json=payload, headers=headers, timeout=timeout)

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
        logging.info(f'Initial data shape: {data.shape}')
        if data.shape[0] == 0:
            data = self.get_data_today_zettablock(central_node)
            logging.info(f'New data shape: {data.shape}')
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
            # Formatting columns for faster aggregations
            data_central_node = data_central_node.astype({address_column: 'category' for address_column in addresses_columns})
            data_central_node = data_central_node.astype({column: 'float' for column in column_aggregations.keys()})
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
            # Doing nunique in category is the slowest thing ever invented by humankind
            temp = temp.astype({address_column: 'object' for address_column in addresses_columns})
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

    def get_response(self, queryrun_id):
        waited_time = 0
        incremenet = 5
        queryrun_status_endpoint = f'https://api.zettablock.com/api/v1/queryruns/{queryrun_id}/status'
        while waited_time < 180:
            res = requests.get(queryrun_status_endpoint, headers=self.headers)
            state = json.loads(res.text)['state']
            if state == 'SUCCEEDED' or state == 'FAILED':
                return state
            time.sleep(incremenet)
            waited_time += incremenet
        logging.info('query timed out, please check status message for details')

    def get_data_today_zettablock(self, address):
        query = """
        SELECT
        *
        FROM
        (
            SELECT
            eth.from_address AS from_address,
            eth.to_address AS to_address,
            eth.from_address_tx AS tx_from,
            eth.to_address_tx AS tx_to,
            SUM(CAST(eth.VALUE AS DOUBLE) / POW(10, eth.decimals)) AS sum_eth_transfer_eth,
            MAX(CAST(eth.VALUE AS DOUBLE) / POW(10, eth.decimals)) AS max_eth_transfer_eth,
            COUNT(eth.symbol) AS n_transactions_eth,
            COUNT(DISTINCT(eth.block_number)) AS n_different_blocks_eth,
            MAX(eth.block_number) - MIN(eth.block_number) AS block_range_eth,
            AVG(tr_eth.gas_price) / POW(10, 9) AS avg_gas_price_gwei_eth,
            (MAX(tr_eth.gas_price) - MIN(tr_eth.gas_price)) / POW(10, 9) AS range_gas_price_gwei_eth
            FROM
            ethereum_mainnet.eth_transfers AS eth
            LEFT JOIN ethereum_mainnet.transactions AS tr_eth ON eth.transaction_hash = tr_eth.hash
            WHERE
            eth.block_time between current_date - interval '2' day and current_date
            AND tr_eth.block_time between current_date - interval '2' day and current_date
            AND (eth.from_address = '{address}'
            OR eth.to_address = '{address}'
            OR eth.from_address_tx = '{address}'
            OR eth.to_address_tx = '{address}')
            GROUP BY
            eth.from_address,
            eth.to_address,
            eth.from_address_tx,
            eth.to_address_tx
        ) AS eth_final FULL OUTER
        JOIN (
            SELECT
            transactions_agg.from_address AS from_address,
            transactions_agg.to_address AS to_address,
            transactions_agg.tx_from AS tx_from,
            transactions_agg.tx_to AS tx_to,
            COUNT(transactions_agg.transaction_hash) AS n_transactions_erc721,
            COUNT(DISTINCT(transactions_agg.transaction_hash)) AS n_unique_transactions_erc721,
            COUNT(DISTINCT(transactions_agg.name)) AS n_unique_tokens_erc721,
            AVG(transactions_agg.n_tokens) AS avg_token_tx_erc721,
            MAX(transactions_agg.n_tokens) AS max_token_tx_erc721,
            AVG(transactions_agg.avg_value) AS avg_value_erc721,
            MAX(transactions_agg.avg_value) AS max_value_erc721,
            COUNT(DISTINCT(transactions_agg.block_number)) AS n_different_blocks_erc721,
            MAX(transactions_agg.block_number) - MIN(transactions_agg.block_number) AS block_range_erc721,
            AVG(transactions_agg.avg_gas_price) / POW(10, 9) AS avg_gas_price_gwei_erc721,
            (
                MAX(transactions_agg.avg_gas_price) - MIN(transactions_agg.avg_gas_price)
            ) / POW(10, 9) AS range_gas_price_gwei_erc721
            FROM
            (
                SELECT
                erc721.from_address,
                erc721.to_address,
                erc721.transaction_hash,
                erc721.contract_address,
                erc721.name,
                tr.from_address AS tx_from,
                tr.to_address AS tx_to,
                COUNT(erc721.token_id) AS n_tokens,
                AVG(tr.value) / POW(10, 18) AS avg_value,
                AVG(erc721.block_number) AS block_number,
                AVG(tr.gas_price) AS avg_gas_price
                FROM
                ethereum_mainnet.erc721_evt_transfer AS erc721
                LEFT JOIN ethereum_mainnet.transactions AS tr ON erc721.transaction_hash = tr.hash
                WHERE
                erc721.block_time between current_date - interval '2' day and current_date
                AND tr.block_time between current_date - interval '2' day and current_date
                AND (erc721.from_address = '{address}'
                OR erc721.to_address = '{address}'
                OR tr.from_address = '{address}'
                OR tr.to_address = '{address}')
                GROUP BY
                erc721.from_address,
                erc721.to_address,
                erc721.transaction_hash,
                erc721.contract_address,
                erc721.name,
                tr.from_address,
                tr.to_address
            ) AS transactions_agg
            GROUP BY
            transactions_agg.from_address,
            transactions_agg.to_address,
            transactions_agg.tx_from,
            transactions_agg.tx_to
        ) AS erc721_final USING (from_address, to_address, tx_from, tx_to) FULL OUTER
        JOIN (
            SELECT
            erc20.from_address AS from_address,
            erc20.to_address AS to_address,
            tr.from_address AS tx_from,
            tr.to_address AS tx_to,
            SUM(
                CAST(erc20.VALUE AS DOUBLE) * all_prices.price / POW(10, erc20.decimals)
            ) AS sum_usd_price_erc20,
            MAX(
                CAST(erc20.VALUE AS DOUBLE) * all_prices.price / POW(10, erc20.decimals)
            ) AS max_usd_price_erc20,
            COUNT(erc20.symbol) AS n_transactions_erc20,
            COUNT(DISTINCT(erc20.block_number)) AS n_different_blocks_erc20,
            COUNT(DISTINCT(erc20.symbol)) AS n_tokens_erc20,
            COUNT(DISTINCT(erc20.contract_address)) AS n_different_contracts_erc20,
            MAX(erc20.block_number) - MIN(erc20.block_number) AS block_range_erc20,
            AVG(tr.gas_price) / POW(10, 9) AS avg_gas_price_gwei_erc20,
            (MAX(tr.gas_price) - MIN(tr.gas_price)) / POW(10, 9) AS range_gas_price_gwei_erc20
            FROM
            ethereum_mainnet.erc20_evt_transfer erc20
            LEFT JOIN ethereum_mainnet.transactions tr ON erc20.transaction_hash = tr.hash
            LEFT JOIN prices.usd all_prices ON erc20.symbol = all_prices.symbol
            AND date_trunc('minute', erc20.block_time) = all_prices.minute
            AND erc20.contract_address = LOWER(all_prices.ethereum_token_address)
            WHERE
            erc20.block_time between current_date - interval '2' day and current_date
            AND tr.block_time between current_date - interval '2' day and current_date
            AND all_prices.minute between current_date - interval '2' day and current_date
            AND (erc20.from_address = '{address}'
            OR erc20.to_address = '{address}'
            OR tr.from_address = '{address}'
            OR tr.to_address = '{address}')
            GROUP BY
            erc20.from_address,
            erc20.to_address,
            tr.from_address,
            tr.to_address
        ) AS erc20_final USING (from_address, to_address, tx_from, tx_to) 
        where from_address = '{address}'
        or to_address = '{address}'
        or tx_from = '{address}'
        or tx_to = '{address}'
        """
        logging.info(f'Getting data from today from zettablock for address: {address}')
        in_query = {"query": query.format(address=address.lower()), "resultCacheExpireMillis": 1000*60*60}
        response = requests.post(self.data_lake_query_url, json=in_query, headers=self.headers)
        if response.status_code != 200:
            logging.info(f'Error getting data from zettablock: {response.text}')
            return None
        
        query_id = response.json()['id']
        data_lake_submission_endpoints = f'https://api.zettablock.com/api/v1/queries/{query_id}/trigger'
        res = requests.post(data_lake_submission_endpoints, headers=self.headers, data='{}')

        queryrun_id = res.json()['queryrunId']
        query_success = self.get_response(queryrun_id)
        if query_success == 'SUCCEEDED':
            # Fetch result from queryrun id
            params = {'includeColumnName': 'true'}
            queryrun_result_endpoint = f'https://api.zettablock.com/api/v1/stream/queryruns/{queryrun_id}/result'
            # if the result is huge, consider using stream and write to a file
            query_response = requests.get(queryrun_result_endpoint, headers=self.headers, params=params)
        else:
            logging.info('query failed, please check status message for details')
            return None
        df = pd.DataFrame([lines.split(',') for lines in query_response.text.split('\n')])
        df.columns = df.iloc[0]
        df.drop(0, inplace=True)
        df.drop(df.tail(1).index,inplace=True)
        df = df.reset_index(drop=True)
        return df
