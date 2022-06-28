import json
import logging
import time
from datetime import datetime

import pandas as pd
import requests


class FortaExplorer:

    def empty_alerts(self) -> pd.DataFrame:
        df_forta = pd.DataFrame(columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])
        return df_forta

    def alerts_by_bot(self, bot_id: str, alert_name: str, contract_address: str, start_date: datetime, end_date: datetime) -> pd.DataFrame:
        url = "https://api.forta.network/graphql"

        df_forta = self.empty_alerts()
        json_data = ""
        first_run = True
        count = 0
        while (json_data == "" or json_data['data']['alerts']['pageInfo']['hasNextPage']):
            query = """query exampleQuery {
                    alerts(
                        input: {
                            first: 2000
                            AFTER_CLAUSE
                            BLOCK_RANGE_CLAUSE
                            BOT_CLAUSE
                            ALERT_NAME_CLAUSE
                            CONTRACT_ADDRESS_CLAUSE
                        }
                    ) {
                        pageInfo {
                        hasNextPage
                        endCursor {
                            alertId
                            blockNumber
                        }
                        }
                        alerts {
                        createdAt
                        name
                        protocol
                        findingType
                        source {
                            transactionHash
                            block {
                            number
                            chainId
                            }
                            bot {
                            id
                            }
                        }
                        severity
                        metadata
                        alertId
                        description
                        addresses
                        contracts {
                            address
                            name
                            projectId
                        }
                        hash
                        }
                    }
                    }"""

            after_clause = ""
            if(first_run is False):
                blockNumber = json_data['data']['alerts']['pageInfo']['endCursor']['blockNumber']
                alertId = json_data['data']['alerts']['pageInfo']['endCursor']['alertId']
                after_clause = """after: {{blockNumber:{0}, alertId:"{1}"}}""".format(blockNumber, alertId)

            # this is a bit hacky
            query = query.replace("AFTER_CLAUSE", after_clause)
            query = query.replace("BLOCK_RANGE_CLAUSE", """blockDateRange: {{ startDate: "{0}", endDate: "{1}" }}""".format(datetime.strftime(start_date, "%Y-%m-%d"), datetime.strftime(end_date, "%Y-%m-%d")))
            query = query.replace("BOT_CLAUSE", f"""bots: ["{bot_id}"]""")
            query = query.replace("ALERT_NAME_CLAUSE", f"""alertName: "{alert_name}" """)
            query = query.replace("CONTRACT_ADDRESS_CLAUSE", f"""addresses: ["{contract_address}"]""")

            retries = 1
            wait = 30
            success = False
            while not success:
                try:
                    count += 1
                    r = requests.post(url, json={'query': query})
                    if r.status_code == 200:
                        success = True
                    else:
                        raise Exception("status code: {}".format(r.status_code))
                except Exception as e:
                    logging.warn(f"Unable to retrieve alerts {r.status_code} , {e}")
                    logging.warn("Sleeping 30sec" + str(count))
                    time.sleep(wait)
                    retries += 1
                    if retries > 30:
                        raise Exception("Unable to retrieve alerts even after repeated retries. Pls check logs")

            json_data = json.loads(r.text)
            df_data = json_data['data']['alerts']['alerts']
            df_forta = pd.concat([pd.DataFrame(df_data), df_forta])
            df_forta["createdAt"] = pd.to_datetime(df_forta["createdAt"], utc=True)

            first_run = False
            count += 1

        return df_forta
