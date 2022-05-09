import time
import requests
import json
import pandas as pd
from datetime import datetime
import logging


class FortaExplorer:

    def empty_alerts(self) -> pd.DataFrame:
        df_forta = pd.DataFrame(columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])
        return df_forta

    def alerts_by_agent(self, agent_id: str, start_date: datetime, end_date: datetime, results_limit: int = 0) -> pd.DataFrame:
        count = 1
        url = "https://api.forta.network/graphql"

        df_forta = self.empty_alerts()
        json_data = ""
        first_run = True
        count = 0
        while (json_data == "" or json_data['data']['alerts']['pageInfo']['hasNextPage']):
            query = """query exampleQuery {
                    # first 5 alerts
                    alerts(
                        input: {
                            first: 2000
                            AFTER_CLAUSE
                            BLOCK_RANGE_CLAUSE
                            AGENT_CLAUSE
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
                            agent {
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
            query = query.replace("AGENT_CLAUSE", f"""agents: ["{agent_id}"]""")

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

            first_run = False
            count += 1

            if(results_limit != 0 and count * 100 > results_limit):
                break

        return df_forta
