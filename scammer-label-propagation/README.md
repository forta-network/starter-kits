# Large Tether Transfer Agent

## Description

This agent propagates scammer labels towards unlabeled addresses. The flow is as follows:
1. A new label is published in an alert by one of the bots this agent is subscribed to. If the confidence is over a certain threshold, it triggers the whole process
1. Based on the address that was labeled as attacker, it collects the first order neighbours (any address that had a transaction from/to the central node). From every neighbour, it collects a representation of the address with aggregated measures, and of the transactions between any two addresses in the graph.
1. Using forta alerts, and subscribed bots, all the labels (both positive and negative) for any of the addresses are collected, and will be used afterwards.
1. Using the previous data a Graph Neural Network is trained. This Neural Network consists of two [TransformerConv](https://pytorch-geometric.readthedocs.io/en/latest/generated/torch_geometric.nn.conv.TransformerConv.html#torch-geometric-nn-conv-transformerconv) layers and two dense layers. It is written using pytorch and pytorch_geometric. The model uses these types of layers because they are compatible with multiple edge features simultaneously. For more information on how this layers work, please refer to the original [paper](https://arxiv.org/abs/2009.03509).
1. The model doesn't have all the information from every node, therefore the agent uses semi-supervised learning to learn from the known labels, and then it predicts on all the addresses that there is no information. From within those, when the model is confident (over a parameter) than an address is an attacker, this address is the published as findings.

## Supported Chains

- Ethereum
- Other chains are not supported right now, as they would need an additional set of queries per call, and the other chains generate way less alerts at the moment. 

## Alerts

Describe each of the type of alerts fired by this agent

- SCAMMER-LABEL-PROPAGATION-1
  - Fired when an address that was previously unlabeled (based on the subscribed bots and configured sensitivity)
  is marked as a potential attacker
  - 'name is set to 'scammer-label-propagation'
  - 'description' is set to 'Address marked as scammer by label propagation'
  - 'alert_id' set to 'SCAMMER-LABEL-PROPAGATION-1'
  - 'severity' is set to 'High'
  - 'type' is set to 'Scam'
  - Labels:
    - 'entity' is the marked address
    - 'label' is set to 'scammer-eoa' (there are no contracts)
    - 'confidence' is the probabilities predicted by the model
    - 'entity_type' is set to 'ADDRESS'
    - 'metadata'
      - 'central_node' is set to the node that was used as the center of the graph
      - 'central_node_alert_id' is set to the alert id that triggered the central node
      - 'central_node_alert_name' is set to the name of the alert that triggered the central node
      - 'central_node_alert_hash' is set to the alert hash of the alert that triggered the central node


## Test Data

The data used for the bot may change over time as it depends on transactions between addresses, and the current labels of an address. Nonetheless, there are a set of transactions to validate the behaviour in agent_test.py.
The calls to 'handle_alert' are asynchronous, which means that sending an alert to the agent, will trigger the processing in the background, but will return an empty list. Nonetheless, the results of this experiments can be seen in the logfile. As an example, by running the command

``npm run alert 0x9d31f23b00013114743bee9836517d2978dd70c873105a322e78f254636f61fb``

We will expect to see in the logfile

``
Initializing scammer label propagation bot. Subscribed to bots successfully: {'alertConfig': {'subscriptions': [{'botId': '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23', 'chainId': 1}]}}
0xab01b6fa35daf2d2c6467669ff64a8cc95692514:	Start processing
Alert ATTACK-DETECTOR-ICE-PHISHING:	0.0014028549 s. 1 addresses: 0xab01b6fa35daf2d2c6467669ff64a8cc95692514
src.preprocessing.get_data:21:0xab01b6fa35daf2d2c6467669ff64a8cc95692514	Querying all related addresses
0xab01b6fa35daf2d2c6467669ff64a8cc95692514:	Finished downloading the data
0xab01b6fa35daf2d2c6467669ff64a8cc95692514	Downloading the automatic labels
0xab01b6fa35daf2d2c6467669ff64a8cc95692514:	Finished processing: 3 attackers found
0xab01b6fa35daf2d2c6467669ff64a8cc95692514:	New attacker info: n_predicted_attacker    10.000000
mean_probs_victim        0.064098
mean_probs_attacker      0.935902
Name: 0x63e2e1a7b832481cbe16f688996c4a97bf49593a, dtype: float64
0xab01b6fa35daf2d2c6467669ff64a8cc95692514:	New attacker info: n_predicted_attacker    10.000000
mean_probs_victim        0.064098
mean_probs_attacker      0.935902
Name: 0xa13ea6d6d9b41914c7a36ea15d4186af3aacd268, dtype: float64
0xab01b6fa35daf2d2c6467669ff64a8cc95692514:	New attacker info: n_predicted_attacker    10.000000
mean_probs_victim        0.064098
mean_probs_attacker      0.935902
Name: 0xbf6e4e8642606c585e04c679645f54dda3318b3c, dtype: float64
``

In order to have a synchronous execution of the code, or for debugging purposes, please use the tests provided in `agent_test.py`.