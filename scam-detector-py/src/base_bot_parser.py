import logging
import forta_agent
import re
import pandas as pd
from forta_agent import EntityType


class BaseBotParser:

    ICE_PHISHING_MAPPINGS_DF = pd.read_csv('ice_phishing_mappings.csv')

    @staticmethod
    def get_scammer_addresses(w3, alert_event: forta_agent.alert_event.AlertEvent) -> dict:
        scammer_addresses = dict()
        for index, row in BaseBotParser.ICE_PHISHING_MAPPINGS_DF.iterrows():
            #  bot_id,alert_id,location,attacker_address_location_in_description,metadata_field,address_information
            if row['bot_id'] == alert_event.bot_id and row['alert_id'] in alert_event.alert_id:
                if row['location'] == 'description':
                    description = alert_event.alert.description.lower()
                    loc = int(row["attacker_address_location_in_description"])
                    scammer_addresses[description[loc:42+loc]] = row["address_information"]
                elif row['location'] == 'metadata':
                    if row['metadata_field'] in alert_event.alert.metadata.keys():
                        metadata = alert_event.alert.metadata[row["metadata_field"]]
                        for address in re.findall(r"0x[a-fA-F0-9]{40}", metadata):
                            scammer_addresses[address.lower()] = row["address_information"]
                elif row['location'] == 'tx_to':
                    scammer_addresses[w3.eth.get_transaction(alert_event.transaction_hash)['to'].lower()] = row["address_information"]

        return scammer_addresses