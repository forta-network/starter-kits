import ast
import re
from os import environ
from functools import lru_cache
from timeit import default_timer as timer

import backoff
from expiringdict import ExpiringDict
import requests
import pandas as pd
import numpy as np

from src.utils.logger import logger
from src.utils.storage import get_secrets

query_id_cache = ExpiringDict(max_len=10, max_age_seconds=1800)


@lru_cache(maxsize=1_000_000)
@backoff.on_exception(
    backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=None
)
def zettablock_api(url: str, query: str, addresses: str):
    # converting addresses from str to list because lru cache can only hash strings
    variables = {"addresses": addresses.split(",")}
    payload = {"query": query, "variables": variables}
    headers = {
        "accept": "application/json",
        "X-API-KEY": environ["ZETTABLOCK_API_KEY"],
        "content-type": "application/json",
    }
    response = requests.post(url, json=payload, headers=headers)
    data = response.json()["data"]["records"]
    return data


def get_query_id(query_name):
    if query_name in query_id_cache:
        return query_id_cache[query_name]
    secrets = get_secrets()
    query_id_cache[query_name] = secrets["queryIds"][query_name]
    return query_id_cache[query_name]


def get_eoa_tx_stats(addresses):
    url = (
        f"https://api.zettablock.com/api/v1/dataset/{get_query_id('EOA_STATS')}/graphql"
    )

    query = "query($addresses: [String!]!) {   records(filter: { eoa: { in: $addresses } }) {     eoa,     num_transactions,     total_time,     total_outgoing_value,     total_incoming_value,     in_ratio,     from_address_nunique,     from_address_count_unique_ratio,     ratio_from_address_nunique,     in_block_number_std,     unique_from_friends,     unique_to_friends   } }"

    data = zettablock_api(url, query, ",".join(addresses))
    df = pd.DataFrame(data).fillna(0)
    df["unique_to_friends"] = df["unique_to_friends"].tolist()
    df["unique_from_friends"] = df["unique_from_friends"].tolist()

    return df, df["eoa"].tolist()


def get_from_in_stats(addresses):
    min_std = 0.0
    median_timespan = 0.0
    if len(addresses) == 0:
        return min_std, median_timespan

    url = f"https://api.zettablock.com/api/v1/dataset/{get_query_id('FROM_IN')}/graphql"

    query = "query($addresses: [String!]!) {records(filter: { eoa: { in: $addresses } }) {eoa, from_in_std_val, from_in_timespan }}"
    data = zettablock_api(url, query, ",".join(addresses))
    df = pd.DataFrame(data).fillna(0)

    min_std = np.min(df["from_in_std_val"])
    median_timespan = np.median(df["from_in_timespan"])

    return min_std, median_timespan


def get_from_out_stats(addresses):
    min_std, block_std_median = 0.0, 0.0
    if len(addresses) == 0:
        return min_std, block_std_median

    url = (
        f"https://api.zettablock.com/api/v1/dataset/{get_query_id('FROM_OUT')}/graphql"
    )

    query = "query($addresses: [String!]!) {records(filter: { eoa: { in: $addresses } }) {eoa, from_out_std_block, from_out_std_val}}"
    data = zettablock_api(url, query, ",".join(addresses))
    df = pd.DataFrame(data).fillna(0)

    min_std = np.min(df["from_out_std_val"])
    block_std_median = np.median(df["from_out_std_block"])

    return min_std, block_std_median


def get_to_in_stats(addresses, total_eth):
    if len(addresses) == 0:
        return dict(
            sum_min=0.0,
            sum_median=0.0,
            sum_median_ratio=0.0,
            min_min=0.0,
            block_std_median=0.0,
        )

    url = f"https://api.zettablock.com/api/v1/dataset/{get_query_id('TO_IN')}/graphql"

    query = "query($addresses: [String!]!) {records(filter: { eoa: { in: $addresses } }) {eoa, to_in_min_val, to_in_median_val, to_in_std_block }}"
    data = zettablock_api(url, query, ",".join(addresses))
    df = pd.DataFrame(data).fillna(0)

    sum_median = np.sum(df["to_in_median_val"])
    stats = dict(
        sum_min=np.sum(df["to_in_min_val"]),
        sum_median=sum_median,
        sum_median_ratio=(sum_median / total_eth),
        min_min=np.min(df["to_in_min_val"]),
        block_std_median=np.median(df["to_in_std_block"]),
    )

    return stats


def get_to_out_stats(addresses):
    min_std = 0.0

    if len(addresses) == 0:
        return min_std

    url = f"https://api.zettablock.com/api/v1/dataset/{get_query_id('TO_OUT')}/graphql"

    query = "query($addresses: [String!]!) {records(filter: { eoa: { in: $addresses } }) {eoa, to_out_std_val }}"
    data = zettablock_api(url, query, ",".join(addresses))
    df = pd.DataFrame(data).fillna(0)

    min_std = np.min(df["to_out_std_val"])

    return min_std


def convert_str_to_list(val):
    lst = ast.literal_eval(
        re.sub(r"0x\w+", lambda m: f'"{m.group(0)}"', val.replace("null", "None"))
    )
    return [v for v in lst if v is not None]


def get_features(address, eoa_stats) -> tuple:
    start = timer()
    data = eoa_stats.iloc[0].to_dict()
    to_friends = convert_str_to_list(data["unique_to_friends"])
    from_friends = convert_str_to_list(data["unique_from_friends"])
    total_eth = data["total_incoming_value"] + data["total_outgoing_value"]

    del data["total_incoming_value"]
    del data["total_outgoing_value"]
    del data["unique_to_friends"]
    del data["unique_from_friends"]
    del data["num_transactions"]

    try:
        # get from_in ML features
        (
            data["from_in_min_std"],
            data["from_in_block_timespan_median"],
        ) = get_from_in_stats(from_friends)

        # get from_out ML features
        (
            data["from_out_min_std"],
            data["from_out_block_std_median"],
        ) = get_from_out_stats(from_friends)

        # get to_in ML features
        to_in_stats = get_to_in_stats(to_friends, total_eth)
        data["to_in_sum_min"] = to_in_stats["sum_min"]
        data["to_in_sum_median"] = to_in_stats["sum_median"]
        data["to_in_sum_median_ratio"] = to_in_stats["sum_median_ratio"]
        data["to_in_min_min"] = to_in_stats["min_min"]
        data["to_in_block_std_median"] = to_in_stats["block_std_median"]

        # get to_out ML features
        data["to_out_min_std"] = get_to_out_stats(to_friends)
    except KeyError as e:
        logger.warn(f"incomplete features for {address} {e}: {data}")
        data = None

    end = timer()
    feature_generation_response_time_sec = end - start

    return data, feature_generation_response_time_sec
