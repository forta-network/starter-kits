import time
import timeit
import os
import io
import random
from datetime import datetime
import pandas as pd
import numpy as np
from forta_agent import create_transaction_event, create_alert_event, FindingSeverity, AlertEvent, Label, EntityType
import requests
import agent

from constants import BASE_BOTS, MODEL_ALERT_THRESHOLD_LOOSE, MODEL_FEATURES
from web3_mock import CONTRACT, EOA_ADDRESS_SMALL_TX, Web3Mock, EOA_ADDRESS_LARGE_TX, CONTRACT2
from forta_explorer_mock import FortaExplorerMock
from blockchain_indexer_mock import BlockChainIndexerMock
from utils import Utils

w3 = Web3Mock()
forta_explorer = FortaExplorerMock()
block_chain_indexer = BlockChainIndexerMock()


class TestScamDetector:

    @staticmethod
    def generate_alert(bot_id: str, alert_id: str, description = "", metadata={}, labels=[], transaction_hash = "0x123", alert_hash = '0xabc', timestamp = 0) -> AlertEvent:
        labels_tmp = [] if len(labels) == 0 else labels
        ts = "2022-11-18T03:01:21.457234676Z" if timestamp == 0 else datetime.fromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S.%f123Z")  # 2022-11-18T03:01:21.457234676Z
        alert = {"alert":
                  {"name": "x",
                   "hash": alert_hash,
                   "addresses": [],
                   "description": description,
                   "alertId": alert_id,
                   "createdAt": ts,
                   "source": {"bot": {'id': bot_id}, "block": {"chainId": 1, 'number': 5},  'transactionHash': transaction_hash},
                   "metadata": metadata,
                   "labels": labels_tmp
                  }
                }
        
        return create_alert_event(alert)
    
    @staticmethod
    def filter_findings(findings: list, handler_type: str) -> list:
        findings_result = []
        for finding in findings:
            if 'handler_type' in finding.metadata.keys() and finding.metadata['handler_type'] == handler_type:
                findings_result.append(finding)
        return findings_result

    def test_initialize(self):
        agent.initialize()
        assert agent.INITIALIZED

    # def test_perf_passthrough_alert(self):
    #     global w3
    #     agent.initialize()
    #     agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

    #     shards = Utils.get_total_shards(1)
        
    #     bot_id = "0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732"
    #     alert_id = "NFT-WASH-TRADE"
    #     description = "test Wash Trade on test."
    #     metadata = {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}
    #     global wash_trading_alert_event
    #     wash_trading_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     bot_id = "0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15"
    #     alert_id = "HARD-RUG-PULL-1"
    #     description = "0x8181bad152a10e7c750af35e44140512552a5cd9 deployed a token contract 0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9 that may result in a hard rug pull."
    #     metadata = {"attacker_deployer_address":"0x8181bad152a10e7c750af35e44140512552a5cd9","rugpull_techniques":"HIDDENTRANSFERREVERTS, HONEYPOT","token_contract_address":"0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9"}
    #     global hard_rug_pull_alert_event
    #     hard_rug_pull_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     bot_id = "0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11"
    #     alert_id = "RAKE-TOKEN-CONTRACT-1"
    #     description = "swapExactETHForTokensSupportingFeeOnTransferTokens function detected on Uniswap Router to take additional swap fee."
    #     metadata = {"actualValueReceived":"1.188051244910305019265053e+24","anomalyScore":"0.2226202661207779","attackerRakeTokenDeployer":"0xa0f80e637919e7aad4090408a63e0c8eb07dfa03","feeRecipient":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","from":"0x6c07456233f0e0fd03137d814aacf225f528068d","pairAddress":"0x2b25f23c31a490583ff55fb63cea459c098cc0e8","rakeTokenAddress":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","rakeTokenDeployTxHash":"0xec938601346b2ecac1bd82f7ce025037c09a3d817d00d723efa6fc5507bca5c2","rakedFee":"2.09656102042995003399715e+23","rakedFeePercentage":"15.00","totalAmountTransferred":"1.397707346953300022664768e+24"}
    #     global rake_token_alert_event
    #     rake_token_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     bot_id = "0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4"
    #     alert_id = "SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION"
    #     description = "Likely Soft rug pull has been detected"
    #     metadata = {"alert_hash":"0xd99ed20f397dbe53721e9a3424d0b87bcffb8df09fc2a9fea5748f81f3c7d324 && 0x0de8a4f6e1efff58a43cb20a81dd491e23b5eea32412a7b679129eb7b0638ea1","alert_id":"SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION","bot_id":"0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1","contractAddress":"\"0x27382445B936C1f362CbBC32E3d3fa5947220030\"","deployer":"\"0xa3fe18ced8d32ca601e3b4794856c85f6f56a176\"","token":"\"0xdd17532733f084ee4aa2de4a14993ef363843216\"","txHashes":"\"0x136af8104791a904614df3728a4bacf3bb79854db362e70f65e64a787ca23efa\""}
    #     global soft_rug_pull_alert_event
    #     soft_rug_pull_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     bot_id = "0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502"
    #     alert_id = "ADDRESS-POISONING"
    #     description = "Possible address poisoning transaction."
    #     metadata = {"attackerAddresses":"0x1a1c0eda425a77fcf7ef4ba6ff1a5bf85e4fc168,0x55d398326f99059ff775485246999027b3197955","anomaly_score":"0.0023634453781512603","logs_length":"24","phishingContract":"0x81ff66ef2097c8c699bff5b7edcf849eb4f452ce","phishingEoa":"0xf6eb5da5850a1602d3d759395480179624cffe2c"}
    #     global address_poisoning_alert_event
    #     address_poisoning_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     bot_id = "0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0"
    #     alert_id = "NIP-1"
    #     description = "0x7cfb946f174807a4746658274763e4d7642233df sent funds to 0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183 with ClaimTokens() as input data"
    #     metadata = {"anomalyScore":"0.000002526532805344122","attacker":"0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183","funcSig":"ClaimTokens()","victim":"0x7cfb946f174807a4746658274763e4d7642233df"}
    #     global nip_alert_event
    #     nip_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     bot_id = "0xd9584a587a469f3cdd8a03ffccb14114bc78485657e28739b8036aee7782df5c"
    #     alert_id = "SEAPORT-PHISHING-TRANSFER"
    #     description = "3 SewerPass id/s: 19445,25417,5996 sold on Opensea 🌊 for 0.01 ETH with a floor price of 2.5 ETH"
    #     metadata = {"anomaly_score":"0.5","attackHash":"0x016e615428b93eb914ed85aa2bea6962650dfbff6a112edab58ad9ad2fb70640","buyPrice":"0.005","collectionFloor":"14.999","contractAddress":"0xed5af388653567af2f388e6224dc7c4b3241c544","contractName":"Azuki","currency":"ETH","fromAddr":"0x477849ba81b0944f6261bd0fbd24820bce800dc6","hash":"0xd8ddec3d6b10e8e5fe8dddc4535e065e5c19d5d937ffcd493936d6d0a5d25c14","initiator":"0x24278f2643e90b56a519aef6e612d91dca5257d1","itemPrice":"0.005","market":"Opensea 🌊","profit":"0.005","quantity":"2","toAddr":"0x24278f2643e90b56a519aef6e612d91dca5257d1","tokenIds":"9291,9307","totalPrice":"0.01"}
    #     global fraudulent_seaport_orders_alert_event
    #     fraudulent_seaport_orders_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
    #     alert_id = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS"
    #     description = "0xFB4d3EB37bDe8FA4B52c60AAbE55B3Cd9908EC73 obtained transfer approval for 78 ERC-20 tokens by 195 accounts over period of 4 days."
    #     metadata = {"anomalyScore":"0.00012297740401709194","firstTxHash":"0x5840ac6991b6603de6b05a9da514e5b4d70b15f4bfa36175dd78388915d0b9a9","lastTxHash":"0xf841ffd55ee93da17dd1b017805904ce29c3127dee2db53872234f094d1ce2a0"}
    #     global ice_phishing_alert_event
    #     ice_phishing_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)


    #     #below the alert rates of passhthrough bots across all chains, so very conservative
    #     #wash trading alert rate: 500/day max 
    #     #soft rug pull alert rate: 1000/day max
    #     #hard rug pull alert rate: 300/day max
    #     #rake token alert rate: 10000/day max
    #     #seaport order alert rate: 2000/day max
    #     #ice phishing alert rate: 5000/day max
    #     #address poisoning: 60000/day max
    #     #native ice phishing alert rate: 1000/day max
    #     #alert_detector alert rate: 100/day max
    #     #contract similarity alert rate: 400/day max
    #     #TOTAL: 80000day max

    #     #we have 86400000ms/day, so an alert needs to process in less than 86400000/80000 = 1080ms; given this is for all chains, but there is skew, we multiply that by 2

    #     processing_runs = 10
    #     processing_time_wash_trading_ms = timeit.timeit('agent.detect_scam(w3, wash_trading_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
    #     processing_time_hard_rug_pull_ms = timeit.timeit('agent.detect_scam(w3, hard_rug_pull_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
    #     processing_time_soft_rug_pull_ms = timeit.timeit('agent.detect_scam(w3, soft_rug_pull_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
    #     processing_time_address_poisoning_ms = timeit.timeit('agent.detect_scam(w3, address_poisoning_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
    #     processing_time_fraudulent_seaport_orders_ms = timeit.timeit('agent.detect_scam(w3, fraudulent_seaport_orders_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
    #     processing_time_nip_ms = timeit.timeit('agent.detect_scam(w3, nip_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
    #     processing_time_ice_phishing_ms = timeit.timeit('agent.detect_scam(w3, ice_phishing_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
    #     processing_time_rake_token_ms = timeit.timeit('agent.detect_scam(w3, rake_token_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
    #     processing_time_avg = ((processing_time_wash_trading_ms * (500.0/80000) + processing_time_hard_rug_pull_ms * (300.0/80000) + processing_time_rake_token_ms * (10000.0/80000 +  processing_time_soft_rug_pull_ms * (1000.0/80000)) + 
    #                             processing_time_address_poisoning_ms * (60000.0/80000) + processing_time_fraudulent_seaport_orders_ms * (2000.0/80000) + processing_time_nip_ms * (1000.0/80000 +  processing_time_ice_phishing_ms * (5000.0/80000)))/8)

    #     assert (processing_time_avg/shards) < (1080*2), f"""processing time should be less than {(1080*2)}ms based on the existing sharding config, but is {(processing_time_avg/shards)} ms, 
    #         wash_trading: {processing_time_wash_trading_ms}, 
    #         hard_rug_pull: {processing_time_hard_rug_pull_ms}.
    #         rake_token: {processing_time_rake_token_ms} 
    #         soft_rug_pull: {processing_time_soft_rug_pull_ms} 
    #         nip: {processing_time_nip_ms} 
    #         fraudulent_seaport_orders: {processing_time_fraudulent_seaport_orders_ms} 
    #         address_poisoning: {processing_time_address_poisoning_ms} 
    #         ice_phishing: {processing_time_ice_phishing_ms}
    #         If not, this bot is unlikely to keep up with fast chains, like Polygon"""


    # def test_perf_combination_alert(self):
    #     global w3 
    #     agent.initialize()
    #     agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))
    #     shards = Utils.get_total_shards(1)
    #     agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

    #     bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
    #     alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
    #     description = "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
    #     metadata = {}
    #     global alert_event_1
    #     alert_event_1 = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     bot_id = "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400"
    #     alert_id = "FUNDING-TORNADO-CASH"
    #     description = "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4 interacted with contract 0xcc5f573a93fcab719640f660173b8217664605d3"
    #     metadata = {}
    #     global alert_event_2
    #     alert_event_2 = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     processing_runs = 10
    #     alert_event_1_ms = timeit.timeit('agent.detect_scam(w3, alert_event_1, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
    #     alert_event_2_ms = timeit.timeit('agent.detect_scam(w3, alert_event_2, False)', number=processing_runs, globals=globals()) * 1000 / processing_runs
       
    #     processing_time_avg = ((alert_event_2_ms * (1.0/2) + alert_event_1_ms * (1.0/2))/2)

    #     assert (processing_time_avg/shards) < (1080*2), f"""processing time should be less than {(1080*2)}ms based on the existing sharding config, but is {(processing_time_avg/shards)} ms, 
    #         alert_event_1: {alert_event_1_ms} 
    #         alert_event_2: {alert_event_2_ms}
    #         If not, this bot is unlikely to keep up with fast chains, like Polygon"""
        

    def test_documentation(self):
        # read readme.md

        missing_documentation = ""
        with open("README.md", "r") as f:
            readme = f.read()

            for bot_id, alert_id, alert_logic, alert_id_target in BASE_BOTS:
                found = False
                for line in readme.split("\n"):
                    if bot_id in line and alert_id in line and alert_logic in line:
                        found = True
                # | 0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127 | token impersonation | IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR | PassThrough |
                if not found:
                    missing_documentation += f"| {bot_id} | | {alert_id} | {alert_logic} |\r\n"
        assert len(missing_documentation) == 0, missing_documentation

    def test_detect_wash_trading(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732"
        alert_id = "NFT-WASH-TRADE"
        description = "test Wash Trade on test."
        metadata = {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 2, "this should have triggered a finding for all two EOAs"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-WASH-TRADE", "should be wash trading finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"



    def test_detect_impersonation_token(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127"
        alert_id = "IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR"
        description = "0x3b31724aff894849b90c48024bab38f25a5ee302 deployed an impersonating token contract at 0xb4d91be6d0894de00a3e57c24f7abb0233814c82. It impersonates token USDC (USDC) at 0x115110423f4ad68a3092b298df7dc2549781108e"
        metadata = {"anomalyScore":"0.09375","newTokenContract":"0xb4d91be6d0894de00a3e57c24f7abb0233814c82","newTokenDeployer":"0x3b31724aff894849b90c48024bab38f25a5ee302","newTokenName":"Cross Chain Token","newTokenSymbol":"USDC","oldTokenContract":"0x115110423f4ad68a3092b298df7dc2549781108e","oldTokenDeployer":"0x80ec4276d31b1573d53f5db75841762607bc2166","oldTokenName":"Cross Chain Token","oldTokenSymbol":"USDC"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-IMPERSONATING-TOKEN", "should be impersonated token finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"


    def test_detect_hard_rug_pull(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15"
        alert_id = "HARD-RUG-PULL-1"
        description = "0x8181bad152a10e7c750af35e44140512552a5cd9 deployed a token contract 0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9 that may result in a hard rug pull."
        metadata = {"attacker_deployer_address":"0x8181bad152a10e7c750af35e44140512552a5cd9","rugpull_techniques":"HIDDENTRANSFERREVERTS, HONEYPOT","token_contract_address":"0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-HARD-RUG-PULL", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"


    def test_detect_hard_rug_pull_no_repeat_finding(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15"
        alert_id = "HARD-RUG-PULL-1"
        description = "0x8181bad152a10e7c750af35e44140512552a5cd9 deployed a token contract 0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9 that may result in a hard rug pull."
        metadata = {"attacker_deployer_address":"0x8181bad152a10e7c750af35e44140512552a5cd9","rugpull_techniques":"HIDDENTRANSFERREVERTS, HONEYPOT","token_contract_address":"0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-HARD-RUG-PULL", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"passthrough")
        assert len(findings) == 0, "this should have not triggered another finding"

    def test_detect_repeat_finding(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15"
        alert_id = "HARD-RUG-PULL-1"
        description = "0x8181bad152a10e7c750af35e44140512552a5cd9 deployed a token contract 0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9 that may result in a hard rug pull."
        metadata = {"attacker_deployer_address":"0x8181bad152a10e7c750af35e44140512552a5cd9","rugpull_techniques":"HIDDENTRANSFERREVERTS, HONEYPOT","token_contract_address":"0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-HARD-RUG-PULL", "should be hard rug pull finding"
        assert finding.labels is not None, "labels should not be empty"
        assert finding.labels[0].entity == '0x8181bad152a10e7c750af35e44140512552a5cd9'

        bot_id = "0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11"
        alert_id = "RAKE-TOKEN-CONTRACT-1"
        description = "swapExactETHForTokensSupportingFeeOnTransferTokens function detected on Uniswap Router to take additional swap fee."
        metadata = {"actualValueReceived":"1.188051244910305019265053e+24","anomalyScore":"0.2226202661207779","attackerRakeTokenDeployer":"0x8181bad152a10e7c750af35e44140512552a5cd9","feeRecipient":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","from":"0x6c07456233f0e0fd03137d814aacf225f528068d","pairAddress":"0x2b25f23c31a490583ff55fb63cea459c098cc0e8","rakeTokenAddress":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","rakeTokenDeployTxHash":"0xec938601346b2ecac1bd82f7ce025037c09a3d817d00d723efa6fc5507bca5c2","rakedFee":"2.09656102042995003399715e+23","rakedFeePercentage":"15.00","totalAmountTransferred":"1.397707346953300022664768e+24"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"passthrough")

        assert len(findings) == 2, "this should have triggered a finding for delpoyer EOA for the different alert_id"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-RAKE-TOKEN", "should be hard rug pull finding"
        assert finding.labels is not None, "labels should not be empty"
        assert finding.labels[0].entity == '0x8181bad152a10e7c750af35e44140512552a5cd9'


    def test_detect_rake_token(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11"
        alert_id = "RAKE-TOKEN-CONTRACT-1"
        description = "swapExactETHForTokensSupportingFeeOnTransferTokens function detected on Uniswap Router to take additional swap fee."
        metadata = {"actualValueReceived":"1.188051244910305019265053e+24","anomalyScore":"0.2226202661207779","attackerRakeTokenDeployer":"0xa0f80e637919e7aad4090408a63e0c8eb07dfa03","feeRecipient":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","from":"0x6c07456233f0e0fd03137d814aacf225f528068d","pairAddress":"0x2b25f23c31a490583ff55fb63cea459c098cc0e8","rakeTokenAddress":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","rakeTokenDeployTxHash":"0xec938601346b2ecac1bd82f7ce025037c09a3d817d00d723efa6fc5507bca5c2","rakedFee":"2.09656102042995003399715e+23","rakedFeePercentage":"15.00","totalAmountTransferred":"1.397707346953300022664768e+24"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 2, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-RAKE-TOKEN", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"
        assert finding.labels[0].entity == '0xa0f80e637919e7aad4090408a63e0c8eb07dfa03'
        assert finding.labels[0].label == 'scammer-eoa/rake-token/passthrough'
        found_contract = False
        for label in finding.labels:
            if label.entity == '0x440aeca896009f006eea3df4ba3a236ee8d57d36':
                assert label.label == 'scammer-contract/rake-token/passthrough'
                found_contract = True   
        assert found_contract, "should have found scammer contract"

    def test_detect_soft_rug_pull(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4"
        alert_id = "SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION"
        description = "Likely Soft rug pull has been detected"
        metadata = {"alert_hash":"0xd99ed20f397dbe53721e9a3424d0b87bcffb8df09fc2a9fea5748f81f3c7d324 && 0x0de8a4f6e1efff58a43cb20a81dd491e23b5eea32412a7b679129eb7b0638ea1","alert_id":"SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION","bot_id":"0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1","contractAddress":"\"0x27382445B936C1f362CbBC32E3d3fa5947220030\"","deployer":"\"0xa3fe18ced8d32ca601e3b4794856c85f6f56a176\"","token":"\"0xdd17532733f084ee4aa2de4a14993ef363843216\"","txHashes":"\"0x136af8104791a904614df3728a4bacf3bb79854db362e70f65e64a787ca23efa\""}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-SOFT-RUG-PULL", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"
        assert finding.labels[0].entity == '0xa3fe18ced8d32ca601e3b4794856c85f6f56a176'
        assert finding.labels[0].label == 'scammer-eoa/soft-rug-pull/passthrough'
        found_contract = False
        for label in finding.labels:
            if label.entity == '0xdd17532733f084ee4aa2de4a14993ef363843216':
                assert label.label == 'scammer-contract/soft-rug-pull/passthrough'
                found_contract = True   
        assert found_contract, "should have found scammer contract"


    def test_detect_address_poisoning(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502"
        alert_id = "ADDRESS-POISONING"
        description = "Possible address poisoning transaction."
        metadata = {"attackerAddresses":"0x1a1c0eda425a77fcf7ef4ba6ff1a5bf85e4fc168,0x55d398326f99059ff775485246999027b3197954","anomaly_score":"0.0023634453781512603","logs_length":"24","phishingContract":CONTRACT,"phishingEoa":"0xf6eb5da5850a1602d3d759395480179624cffe2c"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 3, "this should have triggered a finding for all three EOAs"
        finding = findings[0]
        assert "SCAM-DETECTOR-ADDRESS-POISON" in finding.alert_id, "should be address poison finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"



    def test_detect_native_ice_phishing(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0"
        alert_id = "NIP-1"
        description = "0x7cfb946f174807a4746658274763e4d7642233df sent funds to 0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183 with ClaimTokens() as input data"
        metadata = {"anomalyScore":"0.000002526532805344122","attacker":"0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183","funcSig":"ClaimTokens()","victim":"0x7cfb946f174807a4746658274763e4d7642233df"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING", "should be soc eng native ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"

    
    def test_detect_ice_phishing_passthrough(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS"
        description = "0xFB4d3EB37bDe8FA4B52c60AAbE55B3Cd9908EC73 obtained transfer approval for 78 ERC-20 tokens by 195 accounts over period of 4 days."
        metadata = {"anomalyScore":"0.00012297740401709194","firstTxHash":"0x5840ac6991b6603de6b05a9da514e5b4d70b15f4bfa36175dd78388915d0b9a9","lastTxHash":"0xf841ffd55ee93da17dd1b017805904ce29c3127dee2db53872234f094d1ce2a0"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"



    def test_detect_fraudulent_seaport_orders(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac"
        alert_id = "nft-possible-phishing-transfer"
        description = "3 SewerPass id/s: 19445,25417,5996 sold on Opensea 🌊 for 0.01 ETH with a floor price of 2.5 ETH"
        metadata = {"interactedMarket": "opensea","transactionHash": "0x4fff109d9a6c030fce4de9426229a113524903f0babd6de11ee6c046d07226ff","toAddr": "0xBF96d79074b269F75c20BD9fa6DAed0773209EE7","fromAddr": "0x08395C15C21DC3534B1C3b1D4FA5264E5Bd7020C","initiator": "0xaefc35de05da370f121998b0e2e95698841de9b1","totalPrice": "0.001","avgItemPrice": "0.0002","contractAddress": "0xae99a698156ee8f8d07cbe7f271c31eeaac07087","floorPrice": "0.58","timestamp": "1671432035","floorPriceDiff": "-99.97%"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 2, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-FRAUDULENT-NFT-ORDER", "should be nft order finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"

   

    def test_detect_alert_pos_finding_combiner_3_description(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-SUSPICIOUS-TRANSFER"
        description = "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"combination")
        assert len(findings) == 0

        bot_id = "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400"
        alert_id = "FUNDING-TORNADO-CASH"
        description = "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4 interacted with contract 0xcc5f573a93fcab719640f660173b8217664605d3"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"combination")
        finding = findings[0]
        assert len(findings) == 1, "this should have triggered a finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert any(alert_event.alert_hash in str(value) for key, value in finding.metadata.items()), "metadata should contain alert hashes"
        assert any('TORNADO' in str(value) for key, value in finding.metadata.items()), "metadata should contain alert its"
        assert finding.labels is not None, "labels should not be empty"
        label = finding.labels[0]
        assert label.entity == "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4", "entity should be attacker address"
        assert label.label == "scammer-eoa/ice-phishing/combination", "entity should labeled as scam"
        assert label.confidence == 0.62, "entity should labeled with 0.62 confidence"

    def test_detect_alert_pos_finding_combiner_3_metadata(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))


        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"combination")
        assert len(findings) == 0

        bot_id = "0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895"
        alert_id = "AE-MALICIOUS-ADDR"
        description = "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4 obtained"
        metadata = {"amount":"0","from":"0x4f07bb5b0c204da3d1c7a35dab23114ac2145980","malicious_details":"[{'index': '609', 'id': '1ae52e', 'name': 'moonbirdsraffle.xyz', 'type': 'scam', 'url': 'https://moonbirdsraffle.xyz', 'hostname': 'moonbirdsraffle.xyz', 'featured': '0', 'path': '/*', 'category': 'Phishing', 'subcategory': 'Moonbirds', 'description': 'Fake Moonbirds NFT site phishing for funds', 'reporter': 'CryptoScamDB', 'severity': '1', 'updated': '1.65635E+12', 'address': '0x21e13f16838e2fe78056f5fd50251ffd6e7098b4'}]","to":"0x335eeef8e93a7a757d9e7912044d9cd264e2b2d8"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"combination")
        assert len(findings) == 1, "this should have triggered a finding"

    def test_detect_alert_pos_finding_combiner_3_tx_to(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"combination")
        assert len(findings) == 0

        bot_id = "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"
        alert_id = "forta-text-messages-possible-hack"
        description = "description obtained"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"combination")
        assert len(findings) == 1, "this should have triggered a finding"

    def test_detect_alert_no_finding_large_tx_count(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0xdec08cb92a506B88411da9Ba290f3694BE223c26 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"combination")
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"
        alert_id = "forta-text-messages-possible-hack"
        description = "description obtained"
        metadata = {}
        transaction_hash = "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02618"
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, transaction_hash=transaction_hash)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"combination")
        assert len(findings) == 0, "this should have not triggered a finding as the EOA has too many txs"

    def test_detect_alert_pos_nofinding(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99"
        alert_id = "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH"
        description = "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4 funded by TC"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"combination")
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400"
        alert_id = "FUNDING-TORNADO-CASH"
        description = "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4 funded by TC"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"combination")
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2"
        alert_id = "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH"
        description = "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4 laundered funds"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"combination")
        assert len(findings) == 0, "this should have not triggered a finding"


    def test_detect_alert_pos_finding_combiner_with_cluster(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9"
        alert_id = "ENTITY-CLUSTER"
        description = "Entity of size 2 has been identified. Transaction from 0x7a2a13c269b3b908ca5599956a248c5789cc953f created this entity."
        metadata = {"entityAddresses":"0x7A2a13C269b3B908Ca5599956A248c5789Cc953f,0x91C1B58F24F5901276b1F2CfD197a5B73e31F96E"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = agent.detect_scam(w3, alert_event, clear_state_flag=True)
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0x7A2a13C269b3B908Ca5599956A248c5789Cc953f obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"combination")
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"
        alert_id = "forta-text-messages-possible-hack"
        description = "description"
        transaction_hash = "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a026aa"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, transaction_hash=transaction_hash)
       
        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"combination")
        assert len(findings) == 1, "this should have triggered a finding"

    # TODO - fix with new data once version 0.2.2 is deployed and emitted such labels
    def test_detect_alert_similar_contract(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))
        
        bot_id = "0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560"
        alert_id = "NEW-SCAMMER-CONTRACT-CODE-HASH"
        description = "0x731c8288a5a411c2bc0608061a7d8cb08f006685 created contract 0xeac1236222d92fc66e1fd44122c132c4e122859b. It is similar to scam contract 0xd680016776474bd8d9acc98c96c9d7d794cbf9b4 created by 0x713a39d422918d1f9157129426e4b08e6478ef05"

        metadata = {"alert_hash":"0xfb1ba7974e2be1622c2f0db7a9ceb763650c857434d55ba06127a0409ac5ce7d","new_scammer_contract_address":"0xeac1236222d92fc66e1fd44122c132c4e122859b","new_scammer_eoa":"0x731c8288a5a411c2bc0608061a7d8cb08f006685","scammer_contract_address":"0xd680016776474bd8d9acc98c96c9d7d794cbf9b4","scammer_eoa":"0x713a39d422918d1f9157129426e4b08e6478ef05","similarity_hash":"0f18d246eedcd7b1e7df31a0922701da640e6df376675746b1f76199bc06910a","similarity_score":"0.9847575306892395"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "SCAM-DETECTOR-SIMILAR-CONTRACT"
        assert findings[0].metadata['scammer_address'] == "0x731c8288a5a411c2bc0608061a7d8cb08f006685", "metadata should not be empty"
        assert findings[0].metadata['scammer_contract_address'] == "0xeac1236222d92fc66e1fd44122c132c4e122859b", "metadata should not be empty"
        assert findings[0].metadata['existing_scammer_address'] == "0x713a39d422918d1f9157129426e4b08e6478ef05", "metadata should not be empty"
        assert findings[0].metadata['existing_scammer_contract_address'] == "0xd680016776474bd8d9acc98c96c9d7d794cbf9b4", "metadata should not be empty"
        assert findings[0].metadata['similarity_score'] == "0.9847575306892395", "metadata should not be empty"
        assert findings[0].metadata['involved_alert_id_1'] == "SCAM-DETECTOR-RAKE-TOKEN", "metadata should not be empty"
        assert findings[0].metadata['involved_alert_hash_1'] == "0xfb1ba7974e2be1622c2f0db7a9ceb763650c857434d55ba06127a0409ac5ce7d", "metadata should not be empty"

        assert findings[0].labels is not None, "labels should not be empty"
        label = findings[0].labels[0]
        assert label.entity == "0x731c8288a5a411c2bc0608061a7d8cb08f006685", "entity should be attacker address"
        assert label.label == "scammer-eoa/similar-contract/propagation", "entity should labeled as scam"
        assert label.confidence == 0.4, "entity should labeled with 0.7 confidence"

        label = findings[0].labels[1]
        assert label.entity == "0xeac1236222d92fc66e1fd44122c132c4e122859b", "entity should be attacker address"
        assert label.label == "scammer-contract/similar-contract/propagation", "entity should labeled as scam"
        assert label.confidence == 0.4, "entity should labeled with 0.7 confidence"

    def test_put_entity_cluster(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))


        created_at = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f123Z")
        agent.put_entity_cluster(created_at, EOA_ADDRESS_LARGE_TX, EOA_ADDRESS_LARGE_TX+","+EOA_ADDRESS_SMALL_TX)

        cluster_dict = agent.read_entity_clusters(EOA_ADDRESS_LARGE_TX)
        assert EOA_ADDRESS_LARGE_TX in cluster_dict.keys(), "should have cluster for EOA_ADDRESS_LARGE_TX"
        assert EOA_ADDRESS_LARGE_TX+","+EOA_ADDRESS_SMALL_TX == cluster_dict[EOA_ADDRESS_LARGE_TX]

    def test_put_alert(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

       
        timestamp = 1679508064
        alert = TestScamDetector.generate_alert("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-4", timestamp=timestamp)
        agent.put_alert(alert, EOA_ADDRESS_SMALL_TX)
        agent.put_alert(alert, EOA_ADDRESS_SMALL_TX)

        alerts = agent.read_alerts(EOA_ADDRESS_SMALL_TX)
        assert len(alerts) == 1, "should be 1 alert"
        assert ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-4", "0xabc") in alerts, "should be in alerts"

    def test_put_alert_multiple_shards(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))


        timestamp_1 = 1679508064
        shard1 = Utils.get_shard(1, timestamp_1)

        timestamp_2 = timestamp_1 + 1
        shard2 = Utils.get_shard(1, timestamp_2)
        assert shard1 != shard2, "should be different shards"

        alert = TestScamDetector.generate_alert("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-1", timestamp=timestamp_1)
        agent.put_alert(alert, EOA_ADDRESS_SMALL_TX)

        alert = TestScamDetector.generate_alert("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-2", timestamp=timestamp_2)
        agent.put_alert(alert, EOA_ADDRESS_SMALL_TX)

        alerts = agent.read_alerts(EOA_ADDRESS_SMALL_TX)
        assert len(alerts) == 2, "should be 2 alert"
        assert ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-1", "0xabc") in alerts, "should be in alerts"
        assert ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-2", "0xabc") in alerts, "should be in alerts"

    def test_emit_new_manual_finding(self):
        agent.clear_state()
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        findings = agent.emit_manual_finding(w3, True)
        res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/Scam-Detector-ML/scam-detector-py/manual_alert_list.tsv')
        content = res.content.decode('utf-8') if res.status_code == 200 else open('manual_alert_list.tsv', 'r').read()
        df_manual_entries = pd.read_csv(io.StringIO(content), sep='\t')
        assert len(findings) > 0, "this should have triggered manual findings"
        
        for finding in findings:
            address_lower = "0x6939432e462f7dCB6a3Ca39b9723d18a58FE9A65".lower()
            if address_lower in finding.description.lower():
                assert findings[0].alert_id == "SCAM-DETECTOR-MANUAL-ICE-PHISHING", "should be SCAM-DETECTOR-MANUAL-ICE-PHISHING"
                assert findings[0].description == f"{address_lower} likely involved in an attack (SCAM-DETECTOR-MANUAL-ICE-PHISHING, manual)", "wrong description"
                assert findings[0].metadata["reported_by"] == "@CertiKAlert https://twitter.com/CertiKAlert/status/1640288904317378560?s=20"


    def test_scammer_contract_deployment(self):
        agent.clear_state()
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': '0x9e187687cea757a65c7438f8cbfc3afa732dffc5',
                'nonce': 9,
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_scammer_contract_creation(w3, tx_event)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"
        assert findings[0].metadata["scammer_contract_address"] == "0xa781690be56b721a61336b5ec5d904417cdab626".lower(), "wrong scammer_contract"

    def test_scammer_contract_deployment_indirect(self):
        agent.clear_state()
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': "0x9e187687cea757a65c7438f8cbfc3afa732dffc5",
                'to': "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
                'nonce': 9,
            },
            'block': {
                'number': 0
            },
            'logs': [
                    {'address': "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f".lower(),
                    'topics': ["0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9","0x0000000000000000000000008fcbeec40e6926a79c60946544b371773cfa0e78", "0x000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"],
                    'data': f"0x0000000000000000000000002091a6f364e1ea474be9333c6fa3a23ecd604d66000000000000000000000000000000000000000000000000000000000002d7c7"
                 }
            ],
            'receipt': {
                'logs': []
            }
        })
        findings = agent.detect_scammer_contract_creation(w3, tx_event)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"
        assert findings[0].metadata["scammer_contract_address"] == "0x2091a6f364e1ea474be9333c6fa3a23ecd604d66".lower(), "wrong scammer_contract"

    def test_detect_eoa_association(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))
        
        bot_id = "0xcd9988f3d5c993592b61048628c28a7424235794ada5dc80d55eeb70ec513848"
        alert_id = "SCAMMER-LABEL-PROPAGATION-1"
        description = "0x22914a4f5d97f6a3c4fcc1c44c3a13e567c0efeb marked as scammer by label propagation"
        metadata = {"central_node":"0x13549e22de184a881fe3d164612ef15f99f6d4b3","model_confidence":"0.5","central_node_alert_hash":"0xbda39ad1c0a53555587a8bc9c9f711f0cad81fe89ef235a6d79ee905bc70526c","central_node_alert_id":"SCAM-DETECTOR-ICE-PHISHING","central_node_alert_name":"Scam detector identified an EOA with past alerts mapping to scam behavior","graph_statistics":"[object Object]"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "SCAM-DETECTOR-SCAMMER-ASSOCIATION"
        assert findings[0].labels is not None, "labels should not be empty"
        label = findings[0].labels[0]
        assert label.entity == "0x22914a4f5d97f6a3c4fcc1c44c3a13e567c0efeb", "entity should be attacker address"

    def test_build_feature_vector(self):
        # alerts are tuples of (botId, alertId, alertHash)
        alerts = [('0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5', 'FLASHBOTS-TRANSACTIONS', '0x1'),
                  ('0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14', 'ICE-PHISHING-ERC20-PERMIT', '0x2'),
                  ('0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14', 'ICE-PHISHING-ERC721-APPROVAL-FOR-ALL', '0x3'),
                  ('0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14', 'ICE-PHISHING-ERC721-APPROVAL-FOR-ALL', '0x4')
                  ]

        df_expected_feature_vector = pd.DataFrame(columns=agent.MODEL_FEATURES)
        df_expected_feature_vector.loc[0] = np.zeros(len(agent.MODEL_FEATURES))
        df_expected_feature_vector.iloc[0]["0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_FLASHBOTS-TRANSACTIONS"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC20-PERMIT"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL"] = 2
        df_expected_feature_vector.iloc[0]["0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_count"] = 1
        df_expected_feature_vector.iloc[0]["0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_uniqalertid_count"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_count"] = 3
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_uniqalertid_count"] = 2

        df_expected_feature_vector = df_expected_feature_vector.sort_index(axis=1)  # sort columns alphabetically

        df_feature_vector = agent.build_feature_vector(alerts, EOA_ADDRESS_SMALL_TX)
        assert df_feature_vector.equals(df_expected_feature_vector), "should be equal"

    def test_get_score(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        df_expected_feature_vector = pd.DataFrame(columns=agent.MODEL_FEATURES)
        df_expected_feature_vector.loc[0] = np.zeros(len(agent.MODEL_FEATURES))

        df_expected_feature_vector.iloc[0]["0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_NORMAL-TOKEN-TRANSFERS-TX"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS"] = 3
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS"] = 1
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-SUSPICIOUS-APPROVAL"] = 5
        df_expected_feature_vector.iloc[0]["0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_ASSET-DRAINED"] = 3
        df_expected_feature_vector.iloc[0]["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_count"] = 10
        df_expected_feature_vector.iloc[0]["0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_count"] = 3
        df_expected_feature_vector.iloc[0]["0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_count"] = 1

        score = agent.get_model_score(df_expected_feature_vector)
        assert score > MODEL_ALERT_THRESHOLD_LOOSE, "should greater than model threshold"

    def test_get_score_empty_features(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        df_expected_feature_vector = pd.DataFrame(columns=agent.MODEL_FEATURES)
        df_expected_feature_vector.loc[0] = np.zeros(len(agent.MODEL_FEATURES))
        

        score = agent.get_model_score(df_expected_feature_vector)
        assert score < MODEL_ALERT_THRESHOLD_LOOSE, "should less than model threshold"

    def test_scam_critical(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        label = {"label": "Scammer",
                 "confidence": 0.25,
                 "entity": "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99B3821",
                 "entityType": EntityType.Address
                 }

        alerts = {"0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_NORMAL-TOKEN-TRANSFERS-TX": 1,
                  "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL": 4
                 }

        timestamp = datetime.now().timestamp()
        all_findings = []
        count = 1
        for alert_key in alerts.keys():
            num_alerts = alerts[alert_key]
            for i in range(num_alerts):
                bot_id = alert_key.split("_")[0]
                alert_id = alert_key.split("_")[1]
                alert_hash = str(hex(count))
                alert_event = TestScamDetector.generate_alert(bot_id=bot_id, alert_id=alert_id, timestamp=int(timestamp), description=EOA_ADDRESS_SMALL_TX, labels=[label], alert_hash=alert_hash)
                findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"ml")
                print(f"bot_id: {bot_id}, alert_id: {alert_id}, findings len: {len(findings)}")
                all_findings.extend(findings)
                count += 1

        assert len(all_findings) == 3, "should have one finding for EOA/ 2 for contracts created by EOA"
        assert all_findings[0].alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be SCAM-DETECTOR-ICE-PHISHING"
        assert all_findings[0].severity == FindingSeverity.Critical, "should be Critical"

        assert all_findings[0].labels is not None, "labels should not be empty"
        label = all_findings[0].labels[0]
        assert "/ml" in label.label
        assert label.confidence > 0.77 and label.confidence < 0.78, "confidence should be between 0.77 and 0.78"
        



    def test_get_scam_detector_alert_ids(self):
        alert_list = [("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC20-SCAM-PERMIT", "hash1"), ("0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799", "ATTACK-DETECTOR-1", "hash2"), ("0xdba64bc69511d102162914ef52441275e651f817e297276966be16aeffe013b0", "UMBRA-RECEIVE", "hash3")]
        expected_result = {"SCAM-DETECTOR-ICE-PHISHING", "SCAM-DETECTOR-1"}

        actual = agent.get_scam_detector_alert_ids(alert_list)
        assert actual == expected_result

    def test_subscription_model_features(self):
        missing_subscription_str = ""
        
        for feature in MODEL_FEATURES:
            botId1 = feature.split("_")[0]
            alertId1 = feature[len(botId1) + 1:]
            if alertId1 == "count" or alertId1 == "uniqalertid_count":
                continue

            found = False
            for botId, alertId, alert_logic, target_alert_id in BASE_BOTS:
                if botId == botId1 and alertId == alertId1:
                    found = True

            if not found:
                missing_subscription_str += f'("{botId1}", "{alertId1}", "Combination", ""),\r\n'
            
        print(missing_subscription_str) 
        assert missing_subscription_str == "", f"Missing subscription for {missing_subscription_str}"

    def test_fp_mitigation_proper_chain_id(self):
        agent.clear_state()
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        findings = agent.emit_new_fp_finding(w3)
        res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/main/scam-detector-py/fp_list.csv')
        content = res.content.decode('utf-8') if res.status_code == 200 else open('fp_list.csv', 'r').read()
        df_fps = pd.read_csv(io.StringIO(content), sep=',')
        assert len(findings) > 0, "this should have triggered FP findings"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-FALSE-POSITIVE", "should be FP mitigation finding"
        assert finding.labels is not None, "labels should not be empty"

    def test_get_similar_contract_labels(self):
        agent.clear_state()
        agent.initialize()
        similar_contract_labels = agent.get_similar_contract_labels(w3, forta_explorer)

        # from_address was detected first and it propagated its label to the to_address
        from_address = "0xfa8c1a1dddea2c06364c9e6ab31772f020f5efc6"
        from_address_deployer = "0x2320a28f52334d62622cc2eafa15de55f9987ecc"
        to_address = "0xfa8c1a1dddea2c06364c9e6ab31772f020f5efc5"
        to_address_deployer = "0x2320a28f52334d62622cc2eafa15de55f9987eaa"

        assert similar_contract_labels[similar_contract_labels['from_entity'] == from_address].iloc[0]['to_entity'] == to_address
        assert similar_contract_labels[similar_contract_labels['from_entity'] == from_address].iloc[0]['from_entity_deployer'] == from_address_deployer
        assert similar_contract_labels[similar_contract_labels['to_entity'] == to_address].iloc[0]['to_entity_deployer'] == to_address_deployer

    def test_get_scammer_association_labels(self):
        agent.clear_state()
        agent.initialize()
        scammer_association_labels = agent.get_scammer_association_labels(w3, forta_explorer)

        # from_address was detected first and it propagated its label to the to_address
        from_address = "0x3805ad836968b7d844eac2fe0eb312ccc37e4630"
        to_address = "0x3805ad836968b7d844eac2fe0eb312ccc37e463a"

        assert scammer_association_labels[scammer_association_labels['from_entity'] == from_address].iloc[0]['to_entity'] == to_address

    def test_obtain_all_fp_labels_deployed_contracts(self):
        # got address EOA_ADDRESS_SMALL_TX that deployed contract CONTRACT
        agent.clear_state()
        agent.initialize()

        similar_contract_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])
        scammer_association_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])

        fp_labels = agent.obtain_all_fp_labels(w3, EOA_ADDRESS_SMALL_TX, block_chain_indexer, forta_explorer, similar_contract_labels, scammer_association_labels, 1)
        sorted_fp_labels = sorted(fp_labels, key=lambda x: x[0])
        sorted_fp_labels = list(sorted_fp_labels)
        assert len(sorted_fp_labels) == 2, "should have two FP label; one for the EOA, one for the contract"
        assert list(sorted_fp_labels)[0][0] == EOA_ADDRESS_SMALL_TX.lower()
        assert 'scammer-eoa/' in list(sorted_fp_labels)[0][1] 
        assert list(sorted_fp_labels)[1][0] == CONTRACT.lower()
        assert 'scammer-contract/' in list(sorted_fp_labels)[1][1] 

    def test_obtain_all_fp_labels_scammer_association(self):
        # got address EOA_ADDRESS_LARGE_TX that was propagated from address EOA_ADDRESS_SMALL_TX
        agent.clear_state()
        agent.initialize()

        similar_contract_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])
        scammer_association_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])
        scammer_association_labels = scammer_association_labels.append({'from_entity': EOA_ADDRESS_LARGE_TX.lower(), 'to_entity': EOA_ADDRESS_SMALL_TX.lower()}, ignore_index=True)

        fp_labels = agent.obtain_all_fp_labels(w3, EOA_ADDRESS_LARGE_TX, block_chain_indexer, forta_explorer, similar_contract_labels, scammer_association_labels, 1)
        sorted_fp_labels = sorted(fp_labels, key=lambda x: x[0])
        sorted_fp_labels = list(sorted_fp_labels)
        assert len(sorted_fp_labels) == 4, "should have three FP labels; one for each EOA and contract"
        assert list(sorted_fp_labels)[0][0] == EOA_ADDRESS_SMALL_TX.lower()
        assert 'scammer-eoa/' in list(sorted_fp_labels)[0][1] 
        assert list(sorted_fp_labels)[3][0] == EOA_ADDRESS_LARGE_TX.lower()
        assert 'scammer-eoa/' in list(sorted_fp_labels)[3][1]  
       
    def test_obtain_all_fp_labels_similar_contract(self):
        # got address A that deployed contract B; contract B propagated to contract D
        agent.clear_state()
        agent.initialize()

        similar_contract_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])
        similar_contract_labels = similar_contract_labels.append({'from_entity': CONTRACT.lower(), 'from_entity_deployer': EOA_ADDRESS_LARGE_TX.lower(), 'to_entity_deployer': EOA_ADDRESS_SMALL_TX.lower(), 'to_entity': CONTRACT2.lower()}, ignore_index=True)
        scammer_association_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])
        
        fp_labels = agent.obtain_all_fp_labels(w3, EOA_ADDRESS_LARGE_TX, block_chain_indexer, forta_explorer, similar_contract_labels, scammer_association_labels, 1)
        sorted_fp_labels = sorted(fp_labels, key=lambda x: x[0])
        sorted_fp_labels = list(sorted_fp_labels)
        assert len(sorted_fp_labels) == 4, "should have four FP labels; one for each EOA and contract"