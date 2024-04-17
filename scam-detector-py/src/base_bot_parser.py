import logging
import forta_agent
import re
import pandas as pd
from forta_agent import EntityType


class BaseBotParser:

    BASEBOT_PARSING_CONFIG_DF = pd.read_csv('basebot_parsing_config.csv')


    @staticmethod
    def collect_all_metadata(alert_event: forta_agent.alert_event.AlertEvent) -> dict:
        metadata = dict()
        metadata.update(alert_event.alert.metadata)
        for label in alert_event.alert.labels:
            metadata.update(label.metadata)
        return metadata
    
    @staticmethod
    def check_alert_conditions(row, alert_event):
        valid_chain_ids = [1, 250]  # List of valid chain IDs (i.e chains supporting transaction traces)
        is_valid_chain_id = alert_event.alert.chain_id in valid_chain_ids 

        condition_1 = row['alert_id'] == 'NIP-9' and row['metadata_field'] == 'attacker4' and is_valid_chain_id and 'attacker6' in alert_event.alert.metadata.keys()
        condition_2 = row['alert_id'] == 'NIP-9' and row['metadata_field'] == 'attacker3' and is_valid_chain_id and 'attacker5' in alert_event.alert.metadata.keys()

        return condition_1 or condition_2

    @staticmethod
    def get_scammer_urls(w3, alert_event: forta_agent.alert_event.AlertEvent) -> dict: #entity -> findings metadata union labels metadata
        scammer_urls = dict()
       
                    
        for index, row in BaseBotParser.BASEBOT_PARSING_CONFIG_DF.iterrows():
            #  bot_id,alert_id,location,attacker_address_location_in_description,metadata_field,address_information
            #  address information is to further differentiate one type of address vs the other from the same bot alert (e.g. address-poisioning vs address-posioner)

            if row['bot_id'] == alert_event.bot_id and row['alert_id'] in alert_event.alert_id and row["type"] == 'url':
                if row['location'] == 'description':
                    metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                    description = alert_event.alert.description.lower()
                    loc = int(row["attacker_address_location_in_description"])
                    metadata_obj["address_information"] = row["address_information"]
                    for url in re.findall(r"(?:(?:https?|ftp)://)?[\w\-]+(?:\.[\w\-]+)+[\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#]", description):
                        metadata_obj["address_information"] = row["address_information"]
                        scammer_urls[url.lower()] = metadata_obj
                elif row['location'] == 'label':
                    metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                    label_name = row['metadata_field']
                    for label in alert_event.alert.labels:
                        if label.label == label_name and label.entity_type == EntityType.Address:
                            metadata_obj["address_information"] = row["address_information"]
                            scammer_urls[label.entity] = metadata_obj
                elif row['location'] == 'metadata':
                    if row['metadata_field'] in alert_event.alert.metadata.keys():
                        metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                        metadata = metadata_obj[row["metadata_field"]]
                        for url in re.findall(r"(?:(?:https?|ftp)://)?[\w\-]+(?:\.[\w\-]+)+[\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#]", metadata):
                            metadata_obj["address_information"] = row["address_information"]
                            scammer_urls[url.lower()] = metadata_obj
            
        return scammer_urls
    

    @staticmethod
    def get_scammer_addresses(w3, alert_event: forta_agent.alert_event.AlertEvent) -> dict:
        scammer_addresses = dict() #address -> findings metadata union labels metadata
       
                    
        for index, row in BaseBotParser.BASEBOT_PARSING_CONFIG_DF.iterrows():
            #  bot_id,alert_id,location,attacker_address_location_in_description,metadata_field,address_information
            #  address information is to further differentiate one type of address vs the other from the same bot alert (e.g. address-poisioning vs address-posioner)

            #  contract address is also parsed where applicable and added as 'scammer-contracts' set in the metadata 

            if row['bot_id'] == alert_event.bot_id and row['alert_id'] in alert_event.alert_id and row["type"] == 'eoa':
                if row['location'] == 'description':
                    metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                    description = alert_event.alert.description.lower()
                    loc = int(row["attacker_address_location_in_description"])
                    metadata_obj["address_information"] = row["address_information"]
                    metadata_obj["scammer-contracts"] = BaseBotParser.get_scammer_contract_addresses(w3, alert_event)
                    scammer_addresses[description[loc:42+loc]] = metadata_obj
                elif row['location'] == 'label':
                    metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                    label_name = row['metadata_field']
                    for label in alert_event.alert.labels:
                        if label.label == label_name and label.entity_type == EntityType.Address:
                            metadata_obj["address_information"] = row["address_information"]
                            metadata_obj["scammer-contracts"] = BaseBotParser.get_scammer_contract_addresses(w3, alert_event)
                            scammer_addresses[label.entity] = metadata_obj
                elif row['location'] == 'metadata':
                    if row['metadata_field'] in alert_event.alert.metadata.keys():
                        metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                        metadata = metadata_obj[row["metadata_field"]]
                        for address in re.findall(r"0x[a-fA-F0-9]{40}", metadata):
                            metadata_obj["address_information"] = row["address_information"]
                            metadata_obj["scammer-contracts"] = BaseBotParser.get_scammer_contract_addresses(w3, alert_event)
                            if row['alert_id'] != 'NIP-9' or address.lower() not in metadata_obj["scammer-contracts"]:
                                scammer_addresses[address.lower()] = metadata_obj
                elif row['location'] == 'tx_to':
                    metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                    metadata_obj["address_information"] = row["address_information"]
                    metadata_obj["scammer-contracts"] = BaseBotParser.get_scammer_contract_addresses(w3, alert_event)
                    scammer_addresses[w3.eth.get_transaction(alert_event.transaction_hash)['to'].lower()] = metadata_obj
            
        return scammer_addresses
    
    @staticmethod
    def get_scammer_contract_addresses(w3, alert_event: forta_agent.alert_event.AlertEvent) -> set:
        scammer_contract_addresses = set()

        for index, row in BaseBotParser.BASEBOT_PARSING_CONFIG_DF.iterrows():
            # NIP-9 alert's attacker3 is a contract address on Ethereum (and all chains supporting traces) and is an EOA on the rest of the chains
            if row['bot_id'] == alert_event.bot_id and row['alert_id'] in alert_event.alert_id and (row["type"] == 'contract' or  BaseBotParser.check_alert_conditions(row, alert_event)):
                if row['location'] == 'description':
                    metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                    description = alert_event.alert.description.lower()
                    loc = int(row["attacker_address_location_in_description"])
                    scammer_contract_addresses.add(description[loc:42+loc])
                elif row['location'] == 'label':
                    metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                    label_name = row['metadata_field']
                    for label in alert_event.alert.labels:
                        if label.label == label_name and label.entity_type == EntityType.Address:
                            scammer_contract_addresses.add(label.entity)
                elif row['location'] == 'metadata':
                    if row['metadata_field'] in alert_event.alert.metadata.keys():
                        metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                        metadata = metadata_obj[row["metadata_field"]]
                        for address in re.findall(r"0x[a-fA-F0-9]{40}", metadata):
                            scammer_contract_addresses.add(address.lower())
                elif row['location'] == 'tx_to':
                    metadata_obj = BaseBotParser.collect_all_metadata(alert_event)
                    scammer_contract_addresses.add(w3.eth.get_transaction(alert_event.transaction_hash)['to'].lower())

        return scammer_contract_addresses
