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

    def alerts_by_bot(self, bot_id: str, start_date: datetime, end_date: datetime) -> pd.DataFrame:
        url = "https://api.forta.network/graphql"
        chunk_size = 6000

        df_forta = self.empty_alerts()
        json_data = ""
        first_run = True
        count = 0
        while (json_data == "" or json_data['data']['alerts']['pageInfo']['hasNextPage']):
            query = """query exampleQuery {
                    alerts(
                        input: {
                            CHUNKSIZE
                            AFTER_CLAUSE
                            BLOCK_RANGE_CLAUSE
                            BOT_CLAUSE
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
            query = query.replace("CHUNKSIZE", f"first: {chunk_size},")
            query = query.replace("AFTER_CLAUSE", after_clause)
            query = query.replace("BLOCK_RANGE_CLAUSE", """blockDateRange: {{ startDate: "{0}", endDate: "{1}" }}""".format(datetime.strftime(start_date, "%Y-%m-%d"), datetime.strftime(end_date, "%Y-%m-%d")))
            query = query.replace("BOT_CLAUSE", f"""bots: ["{bot_id}"]""")

            retries = 1
            wait = 30
            success = False
            while not success:
                try:
                    count += 1
                    r = requests.post(url, json={'query': query})
                    if r.status_code == 200:
                        success = True
                        if chunk_size < 5000:
                            chunk_size *= 2
                            logging.warning(f"Increasing chunk size to {chunk_size}")
                    else:
                        raise Exception("status code: {}".format(r.status_code))
                except Exception as e:
                    logging.warning(f"Unable to retrieve alerts {r.status_code} , {e}")
                    logging.warning(f"Sleeping {wait}sec. Count {count}.")
                    old_chunk_size = chunk_size
                    chunk_size = int(chunk_size / 2)
                    if(chunk_size < 1):
                        chunk_size = 1
                    query = query.replace(f"first: {old_chunk_size},", f"first: {chunk_size},")
                    logging.warning(f"Reducing chunk size to {chunk_size}")
                    time.sleep(wait)
                    retries += 1
                    if retries > 30:
                        raise Exception("Unable to retrieve alerts even after repeated retries. Pls check logs")

            json_data = json.loads(r.text)
            df_data = json_data['data']['alerts']['alerts']
            df_forta = pd.concat([pd.DataFrame(df_data), df_forta])

            first_run = False
            count += 1

        return df_forta
