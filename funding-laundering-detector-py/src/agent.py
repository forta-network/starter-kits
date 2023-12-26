from __future__ import annotations
import asyncio
import json
import logging

import forta_agent
from forta_agent import get_json_rpc_url, EntityType
from web3 import Web3

from src.analyze_newly_created import is_newly_created
from src.calculate_usd import calculate_usd_for_base_token, update_top_currencies_info, calculate_usd_and_get_symbol
from src.db.db_utils import db_utils
from src.db.controller import init_async_db
from src.findings import FundingLaunderingFindings
from src.mixer_bridge_exchange import check_is_mixer_bridge_exchange
from src.utils import extract_argument
from .constants import WITHDRAW_ETH_FUNCTION_ABI
from src.config import DEFAULT_THRESHOLDS, L2_THRESHOLDS, TRANSFERS_TO_CONFIRM, TEST_MODE, DEX_DISABLE, \
    INFO_ALERTS, BLOCKS_IN_MEMORY_VALUES, MIXER_ADDRESSES
from src.blockexplorer import BlockExplorer

initialized = False

global possible_targets  # store possible targets firstly
global confirmed_targets  # then move them to confirmed

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
CHAIN_ID = web3.eth.chain_id
blockexplorer = BlockExplorer(CHAIN_ID)
NULL_ADDRESS = "0x0000000000000000000000000000000000000000"

DENOMINATOR_COUNT_FUNDING = 0
DENOMINATOR_COUNT_LAUNDERING = 0

with open("./src/abi/token_abi.json", 'r') as abi_file:  # get abi from the file
    ERC20_ABI = json.load(abi_file)

TRANSFER_EVENT_ABI = next((x for x in ERC20_ABI if x.get('name', "") == "Transfer"), None)  # event Transfer erc20

if CHAIN_ID in [42161, 10]:
    thresholds = L2_THRESHOLDS
else:
    thresholds = DEFAULT_THRESHOLDS

blocks_in_memory = BLOCKS_IN_MEMORY_VALUES.get(CHAIN_ID)
mixer_addresses = MIXER_ADDRESSES

async def analyze_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    """
    This function is triggered by handle_transaction using function main().
    It is used to find mixers / cex / dex / bridges and find interactions with them.
    @param transaction_event: Transaction event received from handle_transaction()
    @return: Findings
    """

    findings = []
    global possible_targets
    global confirmed_targets
    global DENOMINATOR_COUNT_FUNDING
    global DENOMINATOR_COUNT_LAUNDERING

    block = int(transaction_event.block_number)
    confirmed_targets_keys = confirmed_targets.keys()

    # means the amount of transferred native token (ETH for 1 chain id etc.)
    if transaction_event.transaction.value > 0:
        from_ = transaction_event.from_.lower()  # transaction's initiator
        to = transaction_event.to.lower()  # transaction's target
        update_possible_targets(from_, block)  # each of them can be cex / dex etc.
        update_possible_targets(to, block)

        # we should know the amount of transfer in USD and native token symbol of this chain
        usd, token = calculate_usd_for_base_token(transaction_event.transaction.value, CHAIN_ID)

        # skip if amount is too small or one of the address is 0x0000...
        if usd > thresholds["TRANSFER_THRESHOLD_IN_USD"] and from_ != NULL_ADDRESS and to != NULL_ADDRESS:
            # FUNDING
            if from_ in confirmed_targets_keys and to not in confirmed_targets_keys:  # if we know initiator...
                DENOMINATOR_COUNT_FUNDING += 1

                if confirmed_targets[from_]['type'] != 'dex' or not DEX_DISABLE:
                    eoa, newly_created = analyze_address(address=to)  # check is target eoa? and is it newly created?
                    if len(findings) < 10 and eoa:
                        # append our finding
                        labels = [
                            {
                                "entity": to,
                                "entity_type": EntityType.Address,
                                "label": "eoa",
                                "confidence": 1.0,
                            },
                            {
                                "entity": from_,
                                "entity_type": EntityType.Address,
                                "label": confirmed_targets[from_]['type'],
                                "confidence": 1.0,
                            },
                        ]
                        if newly_created:
                            findings.append(
                                FundingLaunderingFindings.funding_newly_created(from_, to, usd, token.upper(),
                                                                                confirmed_targets[from_]['type'],
                                                                                transaction_event.hash, labels,
                                                                                DENOMINATOR_COUNT_FUNDING))
                        elif usd >= thresholds["FUNDING_LOW"] or INFO_ALERTS:
                            findings.append(
                                FundingLaunderingFindings.funding(from_, to, usd, token.upper(),
                                                                  confirmed_targets[from_]['type'],
                                                                  transaction_event.hash, labels,
                                                                  DENOMINATOR_COUNT_FUNDING, CHAIN_ID))

            # LAUNDERING
            elif to in confirmed_targets_keys and from_ not in confirmed_targets_keys or to in mixer_addresses.get(CHAIN_ID, []):
            # if we know target...
                DENOMINATOR_COUNT_LAUNDERING += 1

                labels = [
                    {
                        "entity": from_,
                        "entity_type": EntityType.Address,
                        "label": "eoa",
                        "confidence": 1.0,
                    },
                    {
                        "entity": to,
                        "entity_type": EntityType.Address,
                        "label": confirmed_targets[to]['type'],
                        "confidence": 1.0,
                    },
                ]

                if not (confirmed_targets[to]['type'] == 'dex' and DEX_DISABLE) and (
                        usd >= thresholds["LAUNDERING_LOW"] or INFO_ALERTS):

                    eoa, newly_created = analyze_address(address=from_)  # check is target eoa? and is it newly created?
                    if len(findings) < 10 and eoa:
                        # append our finding
                        findings.append(
                            FundingLaunderingFindings.laundering(from_, to, usd, token.upper(), newly_created,
                                                                 confirmed_targets[to]['type'], transaction_event.hash,
                                                                 labels, DENOMINATOR_COUNT_LAUNDERING, CHAIN_ID))

    if CHAIN_ID == 1 and transaction_event.traces:
        for trace in transaction_event.traces:
            value = trace.action.value
            if value == 0 or not isinstance(value, int):
                continue
            from_ = trace.action.from_  # transaction's initiator
            to = trace.action.to  # transaction's target
            update_possible_targets(from_, block)  # each of them can be cex / dex etc.
            update_possible_targets(to, block)

            # we should know the amount of transfer in USD and native token symbol of this chain
            usd, token = calculate_usd_for_base_token(value, CHAIN_ID)

            # skip if amount is too small or one of the address is 0x0000...
            if usd > thresholds["TRANSFER_THRESHOLD_IN_USD"] and from_ != NULL_ADDRESS and to != NULL_ADDRESS:
                # FUNDING
                if from_ in confirmed_targets_keys and to not in confirmed_targets_keys:  # if we know initiator...
                    DENOMINATOR_COUNT_FUNDING += 1

                    labels = [
                        {
                            "entity": to,
                            "entity_type": EntityType.Address,
                            "label": "eoa",
                            "confidence": 1.0,
                        },
                        {
                            "entity": from_,
                            "entity_type": EntityType.Address,
                            "label": confirmed_targets[from_]['type'],
                            "confidence": 1.0,
                        },
                    ]

                    if confirmed_targets[from_]['type'] != 'dex' or not DEX_DISABLE:
                        eoa, newly_created = analyze_address(
                            address=to)  # check is target eoa? and is it newly created?
                        if len(findings) < 10 and eoa:
                            # append our finding
                            if newly_created:
                                findings.append(
                                    FundingLaunderingFindings.funding_newly_created(from_, to, usd, token.upper(),
                                                                                    confirmed_targets[from_]['type'],
                                                                                    transaction_event.hash, labels,
                                                                                    DENOMINATOR_COUNT_FUNDING))
                            elif usd >= thresholds["FUNDING_LOW"] or INFO_ALERTS:
                                findings.append(
                                    FundingLaunderingFindings.funding(from_, to, usd, token.upper(),
                                                                      confirmed_targets[from_]['type'],
                                                                      transaction_event.hash, labels,
                                                                      DENOMINATOR_COUNT_FUNDING, CHAIN_ID))

                # LAUNDERING
                elif to in confirmed_targets_keys and from_ not in confirmed_targets_keys or to in mixer_addresses.get(CHAIN_ID, []):  # if we know target...
                    DENOMINATOR_COUNT_LAUNDERING += 1

                    labels = [
                        {
                            "entity": from_,
                            "entity_type": EntityType.Address,
                            "label": "eoa",
                            "confidence": 1.0,
                        },
                        {
                            "entity": to,
                            "entity_type": EntityType.Address,
                            "label": confirmed_targets[to]['type'],
                            "confidence": 1.0,
                        },
                    ]

                    if not (confirmed_targets[to]['type'] == 'dex' and DEX_DISABLE) and (
                            usd >= thresholds["LAUNDERING_LOW"] or INFO_ALERTS):
                        eoa, newly_created = analyze_address(
                            address=from_)  # check is target eoa? and is it newly created?
                        if len(findings) < 10 and eoa:
                            # append our finding
                            findings.append(
                                FundingLaunderingFindings.laundering(from_, to, usd, token.upper(), newly_created,
                                                                     confirmed_targets[to]['type'],
                                                                     transaction_event.hash, labels,
                                                                     DENOMINATOR_COUNT_LAUNDERING, CHAIN_ID))

    # This part is responsible for the ERC20 token but the logic is basically the same so no comments needed
    for event in [*transaction_event.filter_log(json.dumps(TRANSFER_EVENT_ABI))]:
        from_ = extract_argument(event, 'from').lower()
        to = extract_argument(event, 'to').lower()
        value = extract_argument(event, 'value')
        if from_ == NULL_ADDRESS or to == NULL_ADDRESS:
            continue

        update_possible_targets(from_, block)
        update_possible_targets(to, block)

        # FUNDING
        if from_ in confirmed_targets_keys and to not in confirmed_targets_keys:
            DENOMINATOR_COUNT_FUNDING += 1
            usd, token = calculate_usd_and_get_symbol(web3, event.address.lower(), ERC20_ABI, value)
            if usd > thresholds["TRANSFER_THRESHOLD_IN_USD"] and (confirmed_targets[from_]['type'] != 'dex' or not DEX_DISABLE):
                eoa, newly_created = analyze_address(address=to)
                if len(findings) < 10 and eoa:
                    labels = [
                        {
                            "entity": to,
                            "entity_type": EntityType.Address,
                            "label": "eoa",
                            "confidence": 1.0,
                        },
                        {
                            "entity": from_,
                            "entity_type": EntityType.Address,
                            "label": confirmed_targets[from_]['type'],
                            "confidence": 1.0,
                        },
                    ]

                    if newly_created:
                        findings.append(
                            FundingLaunderingFindings.funding_newly_created(from_, to, usd, token.upper(),
                                                                            confirmed_targets[from_]['type'],
                                                                            transaction_event.hash, labels,
                                                                            DENOMINATOR_COUNT_FUNDING))
                    elif usd >= thresholds["FUNDING_LOW"] or INFO_ALERTS:
                        findings.append(
                            FundingLaunderingFindings.funding(from_, to, usd, token.upper(),
                                                              confirmed_targets[from_]['type'], transaction_event.hash,
                                                              labels, DENOMINATOR_COUNT_FUNDING, CHAIN_ID))

        # LAUNDERING
        elif to in confirmed_targets_keys and from_ not in confirmed_targets_keys or to in mixer_addresses.get(CHAIN_ID, []):
            DENOMINATOR_COUNT_LAUNDERING += 1
            usd, token = calculate_usd_and_get_symbol(web3, event.address.lower(), ERC20_ABI, value)
            if usd > thresholds["TRANSFER_THRESHOLD_IN_USD"] and (
                    confirmed_targets[to]['type'] != 'dex' or not DEX_DISABLE) and (
                    usd >= thresholds["LAUNDERING_LOW"] or INFO_ALERTS):
                eoa, newly_created = analyze_address(address=from_)

                labels = [
                    {
                        "entity": from_,
                        "entity_type": EntityType.Address,
                        "label": "eoa",
                        "confidence": 1.0,
                    },
                    {
                        "entity": to,
                        "entity_type": EntityType.Address,
                        "label": confirmed_targets[to]['type'],
                        "confidence": 1.0,
                    },
                ]

                if len(findings) < 10 and eoa:
                    findings.append(
                        FundingLaunderingFindings.laundering(from_, to, usd, token.upper(), newly_created,
                                                             confirmed_targets[to]['type'], transaction_event.hash,
                                                             labels, DENOMINATOR_COUNT_LAUNDERING, CHAIN_ID))

    withdrawETH_invocations = transaction_event.filter_function(WITHDRAW_ETH_FUNCTION_ABI)

    for invocation in withdrawETH_invocations:
        args = invocation[1]
        from_ = args['address'].lower()
        to = args['destination'].lower()
        value = args['amount']
        if from_ == NULL_ADDRESS or to == NULL_ADDRESS:
            continue

        update_possible_targets(from_, block)
        update_possible_targets(to, block)

        # FUNDING
        if from_ in confirmed_targets_keys and to not in confirmed_targets_keys:
            DENOMINATOR_COUNT_FUNDING += 1
            usd, token = calculate_usd_for_base_token(value, CHAIN_ID)
            if usd > thresholds["TRANSFER_THRESHOLD_IN_USD"] and (confirmed_targets[from_]['type'] != 'dex' or not DEX_DISABLE):
                eoa, newly_created = analyze_address(address=to)
                if len(findings) < 10 and eoa:
                    labels = [
                        {
                            "entity": to,
                            "entity_type": EntityType.Address,
                            "label": "eoa",
                            "confidence": 1.0,
                        },
                        {
                            "entity": from_,
                            "entity_type": EntityType.Address,
                            "label": confirmed_targets[from_]['type'],
                            "confidence": 1.0,
                        },
                    ]

                    if newly_created:
                        findings.append(
                            FundingLaunderingFindings.funding_newly_created(from_, to, usd, token.upper(),
                                                                            confirmed_targets[from_]['type'],
                                                                            transaction_event.hash, labels,
                                                                            DENOMINATOR_COUNT_FUNDING))
                    elif usd >= thresholds["FUNDING_LOW"] or INFO_ALERTS:
                        findings.append(
                            FundingLaunderingFindings.funding(from_, to, usd, token.upper(),
                                                              confirmed_targets[from_]['type'], transaction_event.hash,
                                                              labels, DENOMINATOR_COUNT_FUNDING, CHAIN_ID))

        # LAUNDERING
        elif to in confirmed_targets_keys and from_ not in confirmed_targets_keys or to in mixer_addresses.get(CHAIN_ID, []):
            DENOMINATOR_COUNT_LAUNDERING += 1
            usd, token = calculate_usd_for_base_token(value, CHAIN_ID)
            if usd > thresholds["TRANSFER_THRESHOLD_IN_USD"] and (
                    confirmed_targets[to]['type'] != 'dex' or not DEX_DISABLE) and (
                    usd >= thresholds["LAUNDERING_LOW"] or INFO_ALERTS):
                eoa, newly_created = analyze_address(address=from_)

                labels = [
                    {
                        "entity": from_,
                        "entity_type": EntityType.Address,
                        "label": "eoa",
                        "confidence": 1.0,
                    },
                    {
                        "entity": to,
                        "entity_type": EntityType.Address,
                        "label": confirmed_targets[to]['type'],
                        "confidence": 1.0,
                    },
                ]

                if len(findings) < 10 and eoa:
                    findings.append(
                        FundingLaunderingFindings.laundering(from_, to, usd, token.upper(), newly_created,
                                                             confirmed_targets[to]['type'], transaction_event.hash,
                                                             labels, DENOMINATOR_COUNT_LAUNDERING, CHAIN_ID))


    return findings


def is_eoa(address):
    """
    This small function checks is address EOA or not
    :param address: target address
    :return: bool
    """
    try:
        return web3.eth.getCode(Web3.toChecksumAddress(address)) == b''
    except:
        return False


def analyze_address(address):
    """
    Just aggregates the results from EOA check and from newly_created check
    :param address: target address
    :return: (bool, bool)
    """
    eoa = is_eoa(address)
    newly_created = is_newly_created(address, blockexplorer)

    return eoa, newly_created


def update_possible_targets(address, block):
    """
    This function is responsible for adding address to the dictionaries if they are not exist already. Otherwise, update
    :param address:
    :param block:
    :return:
    """
    global possible_targets
    global confirmed_targets

    if address in confirmed_targets.keys():
        return

    if address not in possible_targets.keys():
        possible_targets[address] = {'amount': 1, 'expire_block': block + blocks_in_memory}
    else:
        possible_targets[address] = {'amount': possible_targets[address]['amount'] + 1,
                                     'expire_block': block + blocks_in_memory}


async def analyze_blocks(block_event: forta_agent.block_event.BlockEvent) -> None:
    """
    This function is triggered by handle_block using function main().
    Actually this function is responsible not for the block analyses but for the data organisation.
    It moves addresses from the possible targets to confirmed and adds them to the database.
    @param block_event: Block event received from handle_block()
    @return:
    """
    global possible_targets
    global confirmed_targets
    if int(block_event.block_number) % 20 == 0:
        update_top_currencies_info()

    block = int(block_event.block_number)

    # Save address that have enough transfers
    newly_confirmed_targets = [k for k, v in possible_targets.items() if v['amount'] >= TRANSFERS_TO_CONFIRM]
    # Remove them from possibles
    possible_targets = {k: v for k, v in possible_targets.items() if
                        v['expire_block'] >= block and v['amount'] < TRANSFERS_TO_CONFIRM}

    # Write do the db
    for confirmed_target in newly_confirmed_targets:
        eoa = is_eoa(address=confirmed_target)
        target_type = check_is_mixer_bridge_exchange(address=confirmed_target, is_eoa=eoa, chain_id=CHAIN_ID)
        confirmed_targets[confirmed_target] = {'type': target_type,
                                               'is_eoa': eoa}
        addresses = db_utils.get_addresses()
        await addresses.paste_row({'address': confirmed_target, 'address_type': target_type, 'is_eoa': eoa})


async def my_initialize():
    """
    This function is initialize pattern, that is used instead the default Forta's initialize() because the block number
    is needed for the initialization
    """
    global initialized
    global possible_targets
    global confirmed_targets

    possible_targets = {}
    confirmed_targets = {}

    with open("./src/gecko_initial.json", 'r') as gecko_initial_file:  # get abi from the file
        gecko_initial = json.load(gecko_initial_file)
    update_top_currencies_info(initial_values=gecko_initial)

    # initialize database tables
    addresses_table = await init_async_db(TEST_MODE)
    db_utils.set_tables(addresses_table)

    # export known pools from the database to the variable
    addresses = await addresses_table.get_all_rows()

    # and count how many data about this pool we have
    for address in addresses:
        confirmed_targets[address.address] = {'type': address.address_type,
                                              'is_eoa': address.is_eoa}

    initialized = True


async def main(event: forta_agent.transaction_event.TransactionEvent | forta_agent.block_event.BlockEvent):
    """
    This function is used to start logic functions in the different threads and then gather the findings
    """
    global initialized
    if not initialized:
        await my_initialize()
    if isinstance(event, forta_agent.transaction_event.TransactionEvent):
        return await asyncio.gather(
            analyze_transaction(event),
        )
    else:
        await asyncio.gather(
            analyze_blocks(event),
        )
        return []


def provide_handle_transaction():
    """
    This function is just a wrapper for the handle_transaction()
    @return:
    """

    def wrapped_handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return [finding for findings in asyncio.run(main(transaction_event)) for finding in findings]

    return wrapped_handle_transaction


def provide_handle_block():
    """
    This function is just a wrapper for the handle_block()
    @return:
    """

    def wrapped_handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
        return [finding for findings in asyncio.run(main(block_event)) for finding in findings]

    return wrapped_handle_block


real_handle_transaction = provide_handle_transaction()


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    """
    This function is used by Forta SDK
    @param transaction_event: forta_agent.transaction_event.TransactionEvent
    @return:
    """

    return real_handle_transaction(transaction_event)


real_handle_block = provide_handle_block()


def handle_block(block_event: forta_agent.block_event.BlockEvent):
    """
    This function is used by Forta SDK
    @param block_event: forta_agent.block_event.BlockEvent
    @return:
    """
    return real_handle_block(block_event)
