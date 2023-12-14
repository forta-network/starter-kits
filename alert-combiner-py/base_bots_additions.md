# Base Bots

The Attack Detector operates by combining alerts from base bots across the four attack stages (Funding, Preparation, Exploitation, Money Laundering). A requirement of a base bot to be utilized in the Attack Detector is as follows:

1. It emits an attacker label, which contains the EOA of the suspected attacker
2. Its alert contains the field `anomaly_score` in its metadata. This value should be normalized in the range of (0-1.0] where 0 is indicative of more anomalous behavior

Adding a bot to the Attack Detector is trivial. The `constants.py` contains a list of all bots. One merely needs to add the bot ID, alert ID, and stage into the `BASE_BOTS` variable. It is highly recommended to add a test that involves the new bot as a needed component in the `agent_test`.

## Different handling

Usually base bots are utilized in a combination logic across the four attack stages. However, the Attack Detector has more flexibility. One can categorize a base bot as a high confidence bot (that way only two instead of three bots need to trigger for an alert to be emitted) or a passthrough bot (only itself is sufficient for an alert to be emitted). Simply add them to `HIGHLY_PRECISE_BOTS` and `PASSTHROUGH_BOTS` lists respectively.

# Non-alert base bots

In addition to base bots that contribute to raising an alert, there are three additional base bot types: FP Mitigation, Entity Clustering, and Victim Identification Bots that influence how the Attack Detector behaves.

## FP Mitigation Bots

FP mitigation bots are base bots with false positive information. As an FP event for an EOA is received, the Attack Detector retains it. If the Attack Detector receives a set of base bot alerts causing it to emit an alert, the FP list is checked first. In the prod version of the Attack Detector, the alert is silently suppressed; in beta, it's emitted as a different alert ID.

In addition, the reactive FP mitigation will go back to past emitted alerts and if FP mitigation alerts have been received for that EOA in the meantime, an FP alert is emitted and the alert is removed.

Adding a FP mitigation is trivial. Simply add it to the `FP_MITIGATION_BOTS` list in `constants.py`. Note, the EOA that is being FP mitigated needs to be at the start of the alert description.

## Victim Identification Bots

Victim identification bots emit information about the victim (name). Victim information is interweaved with the Attack Detector alert based on the transaction hash of the base bot alerts. So the victim bot needs to make its decision based on the transaction hash (e.g. the hash of a contract creation or exploit tx) and the base bot identifying the malicious behavior needs to operate on the same tx hash. If that is the case, the information gets merged using the get_victim_info() function.

To add a victim identification bot:

1. Ensure its source is a tx hash of a tx associated with the attack
2. Ensure it emits the following fields in its metadata: `address1` and `tag1` (the human readable name of the victim)
3. Add it to `VICTIM_IDENTIFICATION_BOTS` in `constants.py`

## Entity Clustering Bot

Entity clustering bots group together sybil EOAs/contracts. This way, even if the malicious behavior is split across addresses (e.g. address A is funding; address B is deploying a contract), the behavior can still be grouped together.

To add a entity clustering bot:

Currently, only one entity clustering bot is supported (set through `ENTITY_CLUSTER_BOT` and `ENTITY_CLUSTER_BOT_ALERT_ID` in `constants.py`). This structure could be changed to a list. It merely needs to emit a comma-separated list of addresses in the alerts metadata `entityAddresses` field.
