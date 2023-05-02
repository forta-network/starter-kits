import torch
from torch_geometric.nn import TransformerConv
import torch.nn.functional as F


class ModelAttention(torch.nn.Module):
    """
    This model implements two layers of transformer graph convolutions, into two dense layers,
    returning the logits.
    """
    def __init__(self, n_node_features, n_edge_attributes, n_classes=2, hidden_size=16,
                 n_heads=5) -> None:
        """
        :param n_node_features: The number of node features
        :param n_edge_attributes: The number of edge attributes
        :param n_classes: The number of classes
        :param hidden_size: The hidden size for the hidden layers
        :param n_heads: The number of heads for the transformer convolutions
        """
        super().__init__()
        self.conv1 = TransformerConv(n_node_features, hidden_size, edge_dim=n_edge_attributes, 
                                n_heads=n_heads)
        self.conv2 = TransformerConv(hidden_size, int(hidden_size / 2), 
                edge_dim=n_edge_attributes, n_heads=n_heads)
        self.linear1 = torch.nn.Linear(int(hidden_size / 2), hidden_size)
        self.linear2 = torch.nn.Linear(hidden_size, n_classes)
    
    def forward(self, x_in):
        """
        Returns logits. to obtain final probabilities needs to use softmax afterwards
        """
        x = F.relu(self.conv1(x_in.x, x_in.edge_index, x_in.edge_attr))
        x = F.relu(self.conv2(x, x_in.edge_index, x_in.edge_attr))
        x = F.relu(self.linear1(x))
        x_out = self.linear2(x)
        return x_out
