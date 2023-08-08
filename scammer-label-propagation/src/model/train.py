import torch
import numpy as np
import torch.nn as nn
import torch.nn.functional as F

from torch_geometric.data import Data
from torch_geometric.loader import DataLoader
from torch_geometric.utils import to_networkx
from sklearn.preprocessing import MinMaxScaler

from src.constants import MODEL_PATH

big_model = torch.load(MODEL_PATH)


def prepare_graph_and_train(node_feature, edge_indexes, edge_features, model_type, loss_function, labels, epochs=201):
    minmax_scaler = MinMaxScaler()
    node_features_torch = torch.Tensor(np.nan_to_num(minmax_scaler.fit_transform(node_feature)))
    edge_indexes_torch = torch.LongTensor(edge_indexes).t()
    edge_features_torch =  torch.nan_to_num(torch.Tensor(edge_features))
    scammer_graph = Data(x=node_features_torch, edge_index=edge_indexes_torch, 
                        edge_attr=edge_features_torch, y=labels)
    netx = to_networkx(scammer_graph)
    # Train the model
    loss_fn = nn.CrossEntropyLoss()
    scammer_dataset = DataLoader([scammer_graph], batch_size=64)
    model = model_type(scammer_graph.num_node_features, scammer_graph.num_edge_features, hidden_size=64)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
    predictions_every_ten = []
    for epoch in range(epochs):
        model.train()
        for iterator in scammer_dataset:
            optimizer.zero_grad()
            original_label = iterator.y
            predictions = model(iterator)
            loss = loss_function(original_label, predictions, loss_fn)
            loss.backward()
            optimizer.step()
        if epoch % 10 == 0:
            model.eval()
            predictions_every_ten.append(F.softmax(model(iterator), dim=1).detach())
    return model, predictions_every_ten, netx


def prepare_graph_and_predict(node_feature, edge_indexes, edge_features, labels):
    global big_model
    minmax_scaler = MinMaxScaler()
    node_features_torch = torch.Tensor(np.nan_to_num(minmax_scaler.fit_transform(node_feature)))
    edge_indexes_torch = torch.LongTensor(edge_indexes).t()
    edge_features_torch =  torch.nan_to_num(torch.Tensor(edge_features))
    scammer_graph = Data(x=node_features_torch, edge_index=edge_indexes_torch, 
                        edge_attr=edge_features_torch, y=labels)
    scammer_dataset = DataLoader([scammer_graph], batch_size=64)
    big_model.eval()
    all_predictions = []
    for iterator in scammer_dataset:
        predictions = big_model(iterator)
        all_predictions.append(F.softmax(predictions, dim=1).detach())
    return torch.cat(all_predictions, axis=0)
