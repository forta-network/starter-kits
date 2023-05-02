import unittest
import src.preprocessing.get_data as get_data
import src.preprocessing.process_data as process_data

class TestAuxiliarFunctions(unittest.TestCase):
    def test_get_all_addresses(self):
        central_node = '0xfb4c68caccfa3ea46a7d9a7b59a3f91b40705194'
        addresses = get_data.get_all_related_addresses(central_node)
        assert len(addresses.split(',')) > 0, "get_all_related_addresses() should return a list of addresses"
    
    def test_collect_data(self):
        central_node = '0xfb4c68caccfa3ea46a7d9a7b59a3f91b40705194'
        data = get_data.collect_data_parallel_parts(central_node)
        assert len(data) == 6, "collect data should collect 6 dataframes"

    def test_together(self):
        central_node = '0xfb4c68caccfa3ea46a7d9a7b59a3f91b40705194'
        data = get_data.collect_data_parallel_parts(central_node)
        all_nodes_dict, node_feature, transactions_overview, edge_indexes, edge_features = process_data.prepare_data(data)
        labels_df = get_data.download_labels_graphql(all_nodes_dict, central_node)

if __name__ == '__main__':
    unittest.main()