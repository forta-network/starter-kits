# Base Bots

The Scam Detector operates by consuming alerts from a variety of base bots. Generally, addition of a base bot requires merely configuration changes. There are three types of base bots.

1. Detection base bots
2. Contract similarity bots
3. EOA association bots

# Detection Base Bots
Detection base bots are likely the list of bots that change most frequently. Any modifications or additions to base bots need to be configured in the scam detector by addition to the `BASE_BOTS` variable of `constants.py` as well as entries to the `basebot_parsing_config.csv`. Addition to the `BASE_BOTS` list will automatically subscribe the scam detector to these base bots.

The entry in `BASE_BOTS` consists of bot_id, alert_id, inclusion type, and threat category. Inclusion type is either `passthrough` or `combination`. For `passthrough`, the alert is simply propagated through the Scam Detector (with some FP mitigation logic applied). A `combination` alert is not passed through, but rather evaluated as part of the machine learning model defined in the `MODEL_FEATURES` variable (note, simply adding a bot as a combination bot does not modify the machine learning model; it merely means the Scam Detector subscribes to the bot and passes along the value as a feature to the model. The model will need to be adjusted to take into account new features.) The threat category is `SCAM-DETECTOR-` plus one of the threat categories listed in `CONFIDENCE_MAPPINGS`. Note, when introducing a new threat category, code changes are required; simply look for an existing threat category with in the code to identify the places where adjustments need to be made.

In addition to specifying the detection base bots in the `BASE_BOTS`, it also needs to be specified in the `basebot_parsing_config.csv`, which essentially tells the Scam Detector where to extract the EOAs and contracts from. Possible values could be the alert description, metadata, tx or associated label. 

Note, if the bot utilizes encryption, you also need to add it to `ENCRYPTED_BOTS` and specify the descryption key (which is stored in secrets.json). Blocksec is an example. 

Once added, the new bot/alert id should be handled by the Scam Detector. It is highly recommended to add a test that involves the new bot as a needed component in the `agent_test` and `base_bot_parser_test.py`.

## Contract Similarity Bot

Currently, we only have one contract similarity bot configured. A new similarity bot could be configured by addition to the `CONTRACT_SIMILARITY_BOTS` with the `CONTRACT_SIMILARITY_BOT_THRESHOLDS` to be utilized. A contract similarity bot would need to emit the following fields in the metadata:
    - new_scammer_contract_address
    - new_scammer_eoa
    - scammer_contract_address
    - scammer_eoa
    - similarity_hash
    - similarity_score

In addition, the deployer of the new contract needs to be extracted. This should be configured in the `basebot_parsing_config.csv`.

# EOA Association Bots

The EOA association bots work similar to the contract similarity bots. A new EOA association bot could be configured by addition to the `EOA_ASSOCIATION_BOTS` with the `EOA_ASSOCIATION_BOT_THRESHOLDS` to be utilized. A eoa association bot would need to emit the following fields in the metadata:
    - central_node
    - central_node_alert_hash
    - central_node_alert_id

In addition, the new EOA needs to be extracted from the alert. This should be configured in the `basebot_parsing_config.csv`.
