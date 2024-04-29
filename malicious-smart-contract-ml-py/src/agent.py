import asyncio
import random
from forta_bot_sdk import scan_base, scan_ethereum, scan_fantom, scan_polygon, scan_arbitrum, scan_avalanche, scan_bsc, scan_optimism, run_health_check, get_chain_id, TransactionEvent, EntityType
from joblib import load
from evmdasm import EvmBytecode
from web3 import AsyncWeb3
from os import environ
from constants import RPC_ENDPOINTS


from constants import (
    BYTE_CODE_LENGTH_THRESHOLD,
    MODEL_THRESHOLD,
    SAFE_CONTRACT_THRESHOLD,
)
from findings import ContractFindings
from logger import logger
from utils import (
    calc_contract_address,
    get_features,
    get_function_signatures,
    get_storage_addresses,
    is_contract,
)
from storage import get_secrets



ML_MODEL = None


async def initialize():
    """
    this function loads the ml model.
    """
    global ML_MODEL
    logger.info("Start loading model")
    ML_MODEL = load("malicious_non_token_model_02_07_23_exp2.joblib")
    logger.info("Complete loading model")

    global CHAIN_ID
    CHAIN_ID = get_chain_id()
    print("Chain ID: ", CHAIN_ID)

    SECRETS_JSON = await get_secrets()
    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON["apiKeys"]["ZETTABLOCK"]


async def exec_model(w3, opcodes: str, contract_creator: str) -> tuple:
    """
    this function executes the model to obtain the score for the contract
    :return: score: float
    """
    score = None
    features, opcode_addresses = await get_features(w3, opcodes, contract_creator)
    score = ML_MODEL.predict_proba([features])[0][1]
    score = round(score, 4)

    return score, opcode_addresses


async def detect_malicious_contract_tx(
    w3, transaction_event: TransactionEvent
) -> list:
    malicious_findings = []
    safe_findings = []


    for trace in transaction_event.traces:
        if trace.type == "create":
            created_contract_address = (
                trace.result.address if trace.result else None
            )
            error = trace.error if trace.error else None
            logger.info(f"Contract created {created_contract_address}")
            if error is not None:
                if transaction_event.from_ == trace.action.from_:
                    nonce = transaction_event.transaction.nonce
                    contract_address = calc_contract_address(w3, trace.action.from_, nonce)
                else:
                    # For contracts creating other contracts, get the nonce using Web3
                    nonce = await w3.eth.getTransactionCount(w3.to_checksum_address(trace.action.from_), transaction_event.block_number)
                    contract_address = calc_contract_address(w3, trace.action.from_, nonce - 1)

                logger.warn(
                    f"Contract {contract_address} creation failed with tx {trace.transactionHash}: {error}"
                )

            # creation bytecode contains both initialization and run-time bytecode.
            creation_bytecode = trace.action.init
            for finding in await detect_malicious_contract(
                w3,
                trace.action.from_,
                created_contract_address,
                creation_bytecode,
                error=error,
                transaction_event=transaction_event
            ):
                if finding.alert_id == "SUSPICIOUS-CONTRACT-CREATION":
                    malicious_findings.append(finding)
                else:
                    safe_findings.append(finding)

    if transaction_event.to is None:
        nonce = transaction_event.transaction.nonce


        created_contract_address = calc_contract_address(
            w3, transaction_event.from_, nonce
        )
        logger.info(f"Contract created {created_contract_address}")
        creation_bytecode = transaction_event.transaction.data
        for finding in await detect_malicious_contract(
            w3,
            transaction_event.from_,
            created_contract_address,
            creation_bytecode,
            transaction_event=transaction_event
        ):
            if finding.alert_id == "SUSPICIOUS-CONTRACT-CREATION":
                malicious_findings.append(finding)
            else:
                safe_findings.append(finding)

    # Reduce findings to 10 because we cannot return more than 10 findings per request
    return (malicious_findings + safe_findings)[:10]


async def detect_malicious_contract(
    w3, from_, created_contract_address, code, error=None, transaction_event=TransactionEvent
) -> list:
    findings = []

    if created_contract_address is not None and code is not None:
        if len(code) > BYTE_CODE_LENGTH_THRESHOLD:
            try:
                opcodes = EvmBytecode(code).disassemble()
            except Exception as e:
                logger.warn(f"Error disassembling evm bytecode: {e}")
            # obtain all the addresses contained in the created contract and propagate to the findings
            storage_addresses = await get_storage_addresses(w3, created_contract_address)
            (
                model_score,
                opcode_addresses,
            ) = await exec_model(w3, opcodes, from_)
            function_signatures = get_function_signatures(w3, opcodes)
            logger.info(f"{created_contract_address}: score={model_score}")

            finding = ContractFindings(
                from_,
                created_contract_address,
                set.union(storage_addresses, opcode_addresses),
                function_signatures,
                model_score,
                MODEL_THRESHOLD,
                error=error,
            )
            if model_score is not None:
                from_label_type = "contract" if await is_contract(w3, from_) else "eoa"
                labels = [
                    {
                        "entity": created_contract_address,
                        "entity_type": EntityType.Address,
                        "label": "contract",
                        "confidence": 1.0,
                    },
                    {
                        "entity": from_,
                        "entity_type": EntityType.Address,
                        "label": from_label_type,
                        "confidence": 1.0,
                    },
                ]

                if model_score >= MODEL_THRESHOLD:
                    labels.extend(
                        [
                            {
                                "entity": created_contract_address,
                                "entity_type": EntityType.Address,
                                "label": "attacker",
                                "confidence": model_score,
                            },
                            {
                                "entity": from_,
                                "entity_type": EntityType.Address,
                                "label": "attacker",
                                "confidence": model_score,
                            },
                        ]
                    )

                    findings.append(
                        finding.malicious_contract_creation(
                            CHAIN_ID,
                            labels,
                            transaction_event.hash
                        )
                    )
                elif model_score <= SAFE_CONTRACT_THRESHOLD:
                    labels.extend(
                        [
                            {
                                "entity": created_contract_address,
                                "entity_type": EntityType.Address,
                                "label": "positive_reputation",
                                "confidence": 1 - model_score,
                            },
                            {
                                "entity": from_,
                                "entity_type": EntityType.Address,
                                "label": "positive_reputation",
                                "confidence": 1 - model_score,
                            },
                        ]
                    )
                    findings.append(
                        finding.safe_contract_creation(
                            CHAIN_ID,
                            labels,
                            transaction_event.hash
                        )
                    )
                else:
                    findings.append(finding.non_malicious_contract_creation(CHAIN_ID, transaction_event.hash))

    return findings



async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider) -> list:
    rpc_url = random.choice(RPC_ENDPOINTS[CHAIN_ID])

    web3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc_url))
    return await detect_malicious_contract_tx(web3, transaction_event)

async def main():
    await initialize()

    await asyncio.gather(
        scan_ethereum({
            'rpc_url': "https://rpc.ankr.com/eth",
            # 'rpc_key_id': "c795687c-5795-4d63-bcb1-f18b5a391dc4",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        # scan_optimism({
        #     'rpc_url': "https://rpc.ankr.com/optimism",
        #     # 'rpc_key_id': "be4bb945-3e18-4045-a7c4-c3fec8dbc3e1",
        #     'local_rpc_url': "10",
        #     'handle_transaction': handle_transaction
        # }),
        # scan_polygon({
        #     'rpc_url': "https://rpc.ankr.com/polygon",
        #     # 'rpc_key_id': "889fa483-ddd8-4fc0-b6d9-baa1a1a65119",
        #     'local_rpc_url': "137",
        #     'handle_transaction': handle_transaction
        # }),
        # scan_base({
        #     'rpc_url': "https://rpc.ankr.com/base",
        #     # 'rpc_key_id': "166a510e-edca-4c3d-86e2-7cc49cd90f7f",
        #     'local_rpc_url': "8453",
        #     'handle_transaction': handle_transaction
        # }),
        # scan_arbitrum({
        #     'rpc_url': "https://rpc.ankr.com/arbitrum",
        #     # 'rpc_key_id': "09037aa1-1e48-4092-ad3b-cf22c89d5b8a",
        #     'local_rpc_url': "42161",
        #     'handle_transaction': handle_transaction
        # }),
        # scan_avalanche({
        #     'rpc_url': "https://rpc.ankr.com/avalanche",
        #     # 'rpc_key_id': "09037aa1-1e48-4092-ad3b-cf22c89d5b8a",
        #     'local_rpc_url': "43114",
        #     'handle_transaction': handle_transaction
        # }),
        # scan_fantom({
        #     'rpc_url': "https://rpc.ankr.com/fantom",
        #     # 'rpc_key_id': "09037aa1-1e48-4092-ad3b-cf22c89d5b8a",
        #     'local_rpc_url': "250",
        #     'handle_transaction': handle_transaction
        # }),
        # scan_bsc({
        #     'rpc_url': "https://rpc.ankr.com/bsc",
        #     'local_rpc_url': "56",
        #     'handle_transaction': handle_transaction
        # }),
        run_health_check()
    )


if __name__ == "__main__":
    asyncio.run(main())
