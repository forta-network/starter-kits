import numpy as np
import pandas as pd


def get_edge_indexes(row, all_nodes_dict) -> tuple:
    """
    Get the indexes of the nodes in the edge
    :param row: row of the dataframe
    :param all_nodes_dict: dictionary of all nodes
    :return: tuple of the indexes of the nodes in the edge
    """
    return (all_nodes_dict[row.from_address], all_nodes_dict[row.to_address])


def calculate_edge_properties(edge, node_feature) -> list:
    """
    Calculate the properties of the edge and normalize them
    :param edge: edge to calculate the properties
    :param node_feature: dataframe with the features of the nodes
    :return: list of the properties of the edge
    """
    np.seterr(invalid='ignore')  # For this function, ignore dividing by 0 as we will clean after
    # this is to make sure that dividing by 0 gives inf/nan
    edge['n_transactions_together'] = np.float64(edge['n_transactions_together'])
    edge['max_value_together_eth'] = np.float64(edge['max_value_together_eth'])
    edge['avg_value_together_eth'] = np.float64(edge['avg_value_together_eth'])
    edge['total_value_together'] = np.float64(edge['total_value_together'])
    edge['n_transactions_together_erc20'] = np.float64(edge['n_transactions_together_erc20'])
    edge['max_usd_together_erc20'] = np.float64(edge['max_usd_together_erc20'])
    edge['avg_usd_together_erc20'] = np.float64(edge['avg_usd_together_erc20'])
    edge['total_usd_together_erc20'] = np.float64(edge['total_usd_together_erc20'])

    # ETH information
    from_n_p_out_eth = edge.n_transactions_together / node_feature.loc[
        edge.from_address, 'n_transactions_out_eth']
    from_max_p_out_eth = edge.max_value_together_eth / node_feature.loc[
        edge.from_address, 'max_value_out_eth']
    from_avg_p_out_eth = edge.avg_value_together_eth / node_feature.loc[
        edge.from_address, 'avg_value_out_eth']
    from_total_p_out_eth = edge.total_value_together / node_feature.loc[
        edge.from_address, 'total_value_out_eth']
    from_n_p_in_eth = edge.n_transactions_together / node_feature.loc[
        edge.to_address, 'n_transactions_in_eth']
    from_max_p_in_eth = edge.max_value_together_eth / node_feature.loc[
        edge.to_address, 'max_value_in_eth']
    from_avg_p_in_eth = edge.avg_value_together_eth / node_feature.loc[
        edge.to_address, 'avg_value_in_eth']
    from_total_p_in_eth = edge.total_value_together / node_feature.loc[
        edge.to_address, 'total_value_in_eth']
    # ERC20 information
    from_n_p_out_erc20 = edge.n_transactions_together_erc20 / node_feature.loc[
        edge.from_address, 'n_transactions_out_erc20']
    from_max_p_out_erc20 = edge.max_usd_together_erc20 / node_feature.loc[
        edge.from_address, 'max_usd_out_erc20']
    from_avg_p_out_erc20 = edge.avg_usd_together_erc20 / node_feature.loc[
        edge.from_address, 'avg_usd_out_erc20']
    from_total_p_out_erc20 = edge.total_usd_together_erc20 / node_feature.loc[
        edge.from_address, 'total_usd_out_erc20']
    from_n_p_in_erc20 = edge.n_transactions_together_erc20 / node_feature.loc[
        edge.to_address, 'n_transactions_in_erc20']
    from_max_p_in_erc20 = edge.max_usd_together_erc20 / node_feature.loc[
        edge.to_address, 'max_usd_in_erc20']
    from_avg_p_in_erc20 = edge.avg_usd_together_erc20 / node_feature.loc[
        edge.to_address, 'avg_usd_in_erc20']
    from_total_p_in_erc20 = edge.total_usd_together_erc20 / node_feature.loc[
        edge.to_address, 'total_usd_in_erc20']
    np.seterr(invalid='warn')  # set warnings for dividing by 0 again
    to_return = [from_n_p_out_eth, from_max_p_out_eth, from_avg_p_out_eth, from_total_p_out_eth, 
            from_n_p_in_eth, from_max_p_in_eth, from_avg_p_in_eth, from_total_p_in_eth,
            from_n_p_out_erc20, from_max_p_out_erc20, from_avg_p_out_erc20, from_total_p_out_erc20,
            from_n_p_in_erc20, from_max_p_in_erc20, from_avg_p_in_erc20, from_total_p_in_erc20]
    # Replace inf with nan
    to_return = [np.nan if np.isinf(x) else x for x in to_return]
    return to_return


def format_empty_values(data_in: dict) -> dict:
    """
    In cases where there are no transactions from some type in one of the tables, this function gives the 
    dataframes the correct colum format
    :param data_in: dictionary with the dataframes
    :return: dictionary with the dataframes with the correct column format
    """
    if data_in['all_eth_transactions'].shape[0] == 0:
        data_in['all_eth_transactions'] = pd.DataFrame(
            columns=['from_address', 'to_address', 'n_transactions_together', 'max_value_together_eth',
                     'avg_value_together_eth', 'total_value_together'])
    if data_in['all_erc20_transactions'].shape[0] == 0:
        data_in['all_erc20_transactions'] = pd.DataFrame(
            columns=['from_address', 'to_address', 'n_transactions_together_erc20', 'max_usd_together_erc20',
                     'avg_usd_together_erc20', 'total_usd_together_erc20'])
    if data_in['eth_in'].shape[0] == 0:
        data_in['eth_in'] = pd.DataFrame(
            columns=['address', 'n_transactions_in_eth', 'max_value_in_eth', 'avg_value_in_eth',
                     'total_value_in_eth'])
    if data_in['eth_out'].shape[0] == 0:
        data_in['eth_out'] = pd.DataFrame(
            columns=['address', 'n_transactions_out_eth', 'max_value_out_eth', 'avg_value_out_eth',
                     'total_value_out_eth'])
    if data_in['erc20_in'].shape[0] == 0:
        data_in['erc20_in'] = pd.DataFrame(
            columns=['address', 'n_transactions_in_erc20', 'max_usd_in_erc20', 'avg_usd_in_erc20',
                     'total_usd_in_erc20'])
    if data_in['erc20_out'].shape[0] == 0:
        data_in['erc20_out'] = pd.DataFrame(
            columns=['address', 'n_transactions_out_erc20', 'max_usd_out_erc20', 'avg_usd_out_erc20',
                     'total_usd_out_erc20'])
    return data_in


def prepare_data(data_in: dict) -> tuple:
    """
    Prepare the data for the graph neural network. This includes:
    - Writing all the transactions together
    - Creating a dictionary of all the nodes
    - Creating a list of all the edges
    - Creating a list of all the properties of the edges
    - Creating a list of all the properties of the nodes
    :param data_in: dictionary with all the data
    :return: list of all the nodes, list of all the edges, list of all the properties of the edges,
    list of all the properties of the nodes
    """
    # Format empty values
    data_in = format_empty_values(data_in)
    # Write all the transactions together
    transactions_overview = pd.merge(
        data_in['all_eth_transactions'], data_in['all_erc20_transactions'],
        how='outer').drop_duplicates().fillna(0)
    # Create a list of all the nodes, and create an ordered dictionary for indexing
    node_feature = data_in['eth_in'].set_index('address').join(
        data_in['eth_out'].set_index('address'), how='outer').join(
        data_in['erc20_in'].set_index('address'), how='outer').join(
        data_in['erc20_out'].set_index('address'), how='outer')
    all_nodes_dict = {node: i for i, node in enumerate(node_feature.index.to_list())}
    # Remove contracts (doesn't work completely)
    transactions_overview = transactions_overview[
        transactions_overview['from_address'].isin(node_feature.index.to_list()) * 
        transactions_overview['to_address'].isin(node_feature.index.to_list())]
    transactions_overview = transactions_overview.reset_index(drop=True)
    # Calculate edges and properties
    edge_indexes = transactions_overview.apply(
        get_edge_indexes, all_nodes_dict=all_nodes_dict, axis=1)
    edge_features = transactions_overview.apply(
        calculate_edge_properties, node_feature=node_feature, axis=1)
    return all_nodes_dict, node_feature, transactions_overview, edge_indexes, edge_features
