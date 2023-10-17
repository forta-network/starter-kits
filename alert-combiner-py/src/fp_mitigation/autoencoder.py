import pickle

import torch
import torch.nn.functional as F
from torch_geometric.nn import HeteroConv, TransformerConv

from src.constants import AE_MODEL_PATH


class HeteroAutoencoderMultiheadMean(torch.nn.Module):
    def __init__(self, address_features=336, transaction_features=83, head_size=12, heads=10, beta=False):
        super(HeteroAutoencoderMultiheadMean, self).__init__()
        self.encoder_conv1 = HeteroConv({
            ('address', 'sends', 'transaction'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('transaction', 'receives', 'address'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('address', 'starts', 'transaction'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
            ('transaction', 'ends', 'address'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
        })
        self.encoder_conv2 = HeteroConv({
            ('address', 'sends', 'transaction'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('transaction', 'receives', 'address'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('address', 'starts', 'transaction'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
            ('transaction', 'ends', 'address'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
        })
        self.encoder_conv3 = HeteroConv({
            ('address', 'sends', 'transaction'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('transaction', 'receives', 'address'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('address', 'starts', 'transaction'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
            ('transaction', 'ends', 'address'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
        })
        self.decoder_conv1 = HeteroConv({
            ('address', 'sends', 'transaction'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('transaction', 'receives', 'address'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('address', 'starts', 'transaction'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
            ('transaction', 'ends', 'address'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
        })
        self.decoder_conv2 = HeteroConv({
            ('address', 'sends', 'transaction'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('transaction', 'receives', 'address'): TransformerConv(-1, head_size, heads=heads, beta=beta),
            ('address', 'starts', 'transaction'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
            ('transaction', 'ends', 'address'): TransformerConv(-1, head_size, heads=heads, edge_dim=-1, beta=beta),
        })
        self.decoder_conv3 = HeteroConv({
            ('address', 'sends', 'transaction'): TransformerConv(-1, transaction_features, heads=heads, concat=False, beta=beta),
            ('transaction', 'receives', 'address'): TransformerConv(-1, address_features, heads=heads, concat=False, beta=beta),
            ('address', 'starts', 'transaction'): TransformerConv(-1, transaction_features, heads=heads, edge_dim=-1, concat=False, beta=beta),
            ('transaction', 'ends', 'address'): TransformerConv(-1, address_features, heads=heads, edge_dim=-1, concat=False, beta=beta),
        })
    
    def forward(self, x_in, edge_index, edge_attr):
        x = self.encode(x_in, edge_index, edge_attr)
        x = self.apply_relu(x)
        x = self.decode(x, x_in, edge_index, edge_attr)
        return x
       
    def apply_relu(self, x):
        x['address'] = F.relu(x['address'])
        x['transaction'] = F.relu(x['transaction'])
        return x
    
    def encode(self, x_in, edge_index, edge_attr):
        x = self.encoder_conv1(x_in, edge_index, edge_attr_dict=edge_attr)
        x = self.apply_relu(x)
        x = self.encoder_conv2(x, edge_index, edge_attr_dict=edge_attr)
        x = self.apply_relu(x)
        x = self.encoder_conv3(x, edge_index, edge_attr_dict=edge_attr)
        x['transaction'] = x['transaction'].mean(axis=0)
        x['address'] = x['address'].mean(axis=0)
        return x
    
    def decode(self, x, x_in, edge_index, edge_attr):
        x['transaction'] = x['transaction'].repeat(x_in['transaction'].shape[0], 1)
        x['address'] = x['address'].repeat(x_in['address'].shape[0], 1)
        x = self.decoder_conv1(x, edge_index, edge_attr_dict=edge_attr)
        x = self.apply_relu(x)
        x = self.decoder_conv2(x, edge_index, edge_attr_dict=edge_attr)
        x = self.apply_relu(x)
        x = self.decoder_conv3(x, edge_index, edge_attr_dict=edge_attr)
        return x
    

class AE:
    def __init__(self) -> None:
        self.model_path = AE_MODEL_PATH
        # with open(AE_MODEL_PATH, 'rb') as f:
        #     self.model = pickle.load(f)
        self.model = HeteroAutoencoderMultiheadMean()
        self.model.load_state_dict(torch.load(self.model_path))
        self.model.eval()

    def encode(self, data):
        with torch.no_grad():
            return self.model.encode(data['normalized_graph'].x_dict, data['normalized_graph'].edge_index_dict, data['normalized_graph'].edge_attr_dict)
