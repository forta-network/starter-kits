import time
import timeit
import os
import random
from datetime import datetime
import pandas as pd
from forta_agent import create_alert_event,FindingSeverity, AlertEvent, Label, EntityType

import agent

from constants import BASE_BOTS
from web3_mock import CONTRACT, EOA_ADDRESS_SMALL_TX, Web3Mock, EOA_ADDRESS_LARGE_TX
from utils import Utils

w3 = Web3Mock()


class TestScamDetector:
    
    

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

    def test_initialize(self):
        agent.initialize()
        assert agent.INITIALIZED

    def test_perf_passthrough_alert(self):
        global w3
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        shards = Utils.get_total_shards(1)
        
        bot_id = "0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732"
        alert_id = "NFT-WASH-TRADE"
        description = "test Wash Trade on test."
        metadata = {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}
        global wash_trading_alert_event
        wash_trading_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        bot_id = "0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15"
        alert_id = "HARD-RUG-PULL-1"
        description = "0x8181bad152a10e7c750af35e44140512552a5cd9 deployed a token contract 0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9 that may result in a hard rug pull."
        metadata = {"attacker_deployer_address":"0x8181bad152a10e7c750af35e44140512552a5cd9","rugpull_techniques":"HIDDENTRANSFERREVERTS, HONEYPOT","token_contract_address":"0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9"}
        global hard_rug_pull_alert_event
        hard_rug_pull_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        bot_id = "0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11"
        alert_id = "RAKE-TOKEN-CONTRACT-1"
        description = "swapExactETHForTokensSupportingFeeOnTransferTokens function detected on Uniswap Router to take additional swap fee."
        metadata = {"actualValueReceived":"1.188051244910305019265053e+24","anomalyScore":"0.2226202661207779","attackerRakeTokenDeployer":"0xa0f80e637919e7aad4090408a63e0c8eb07dfa03","feeRecipient":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","from":"0x6c07456233f0e0fd03137d814aacf225f528068d","pairAddress":"0x2b25f23c31a490583ff55fb63cea459c098cc0e8","rakeTokenAddress":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","rakeTokenDeployTxHash":"0xec938601346b2ecac1bd82f7ce025037c09a3d817d00d723efa6fc5507bca5c2","rakedFee":"2.09656102042995003399715e+23","rakedFeePercentage":"15.00","totalAmountTransferred":"1.397707346953300022664768e+24"}
        global rake_token_alert_event
        rake_token_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        bot_id = "0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4"
        alert_id = "SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION"
        description = "Likely Soft rug pull has been detected"
        metadata = {"alert_hash":"0xd99ed20f397dbe53721e9a3424d0b87bcffb8df09fc2a9fea5748f81f3c7d324 && 0x0de8a4f6e1efff58a43cb20a81dd491e23b5eea32412a7b679129eb7b0638ea1","alert_id":"SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION","bot_id":"0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1","contractAddress":"\"0x27382445B936C1f362CbBC32E3d3fa5947220030\"","deployer":"\"0xa3fe18ced8d32ca601e3b4794856c85f6f56a176\"","token":"\"0xdd17532733f084ee4aa2de4a14993ef363843216\"","txHashes":"\"0x136af8104791a904614df3728a4bacf3bb79854db362e70f65e64a787ca23efa\""}
        global soft_rug_pull_alert_event
        soft_rug_pull_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        bot_id = "0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502"
        alert_id = "ADDRESS-POISONING"
        description = "Possible address poisoning transaction."
        metadata = {"attackerAddresses":"0x1a1c0eda425a77fcf7ef4ba6ff1a5bf85e4fc168,0x55d398326f99059ff775485246999027b3197955","anomaly_score":"0.0023634453781512603","logs_length":"24","phishingContract":"0x81ff66ef2097c8c699bff5b7edcf849eb4f452ce","phishingEoa":"0xf6eb5da5850a1602d3d759395480179624cffe2c"}
        global address_poisoning_alert_event
        address_poisoning_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        bot_id = "0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0"
        alert_id = "NIP-1"
        description = "0x7cfb946f174807a4746658274763e4d7642233df sent funds to 0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183 with ClaimTokens() as input data"
        metadata = {"anomalyScore":"0.000002526532805344122","attacker":"0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183","funcSig":"ClaimTokens()","victim":"0x7cfb946f174807a4746658274763e4d7642233df"}
        global nip_alert_event
        nip_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        bot_id = "0xd9584a587a469f3cdd8a03ffccb14114bc78485657e28739b8036aee7782df5c"
        alert_id = "SEAPORT-PHISHING-TRANSFER"
        description = "3 SewerPass id/s: 19445,25417,5996 sold on Opensea 🌊 for 0.01 ETH with a floor price of 2.5 ETH"
        metadata = {"anomaly_score":"0.5","attackHash":"0x016e615428b93eb914ed85aa2bea6962650dfbff6a112edab58ad9ad2fb70640","buyPrice":"0.005","collectionFloor":"14.999","contractAddress":"0xed5af388653567af2f388e6224dc7c4b3241c544","contractName":"Azuki","currency":"ETH","fromAddr":"0x477849ba81b0944f6261bd0fbd24820bce800dc6","hash":"0xd8ddec3d6b10e8e5fe8dddc4535e065e5c19d5d937ffcd493936d6d0a5d25c14","initiator":"0x24278f2643e90b56a519aef6e612d91dca5257d1","itemPrice":"0.005","market":"Opensea 🌊","profit":"0.005","quantity":"2","toAddr":"0x24278f2643e90b56a519aef6e612d91dca5257d1","tokenIds":"9291,9307","totalPrice":"0.01"}
        global fraudulent_seaport_orders_alert_event
        fraudulent_seaport_orders_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS"
        description = "0xFB4d3EB37bDe8FA4B52c60AAbE55B3Cd9908EC73 obtained transfer approval for 78 ERC-20 tokens by 195 accounts over period of 4 days."
        metadata = {"anomalyScore":"0.00012297740401709194","firstTxHash":"0x5840ac6991b6603de6b05a9da514e5b4d70b15f4bfa36175dd78388915d0b9a9","lastTxHash":"0xf841ffd55ee93da17dd1b017805904ce29c3127dee2db53872234f094d1ce2a0"}
        global ice_phishing_alert_event
        ice_phishing_alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)


        #below the alert rates of passhthrough bots across all chains, so very conservative
        #wash trading alert rate: 500/day max 
        #soft rug pull alert rate: 1000/day max
        #hard rug pull alert rate: 300/day max
        #rake token alert rate: 10000/day max
        #seaport order alert rate: 2000/day max
        #ice phishing alert rate: 5000/day max
        #address poisoning: 60000/day max
        #native ice phishing alert rate: 1000/day max
        #alert_detector alert rate: 100/day max
        #contract similarity alert rate: 400/day max
        #TOTAL: 80000day max

        #we have 86400000ms/day, so an alert needs to process in less than 86400000/80000 = 1080ms; given this is for all chains, but there is skew, we multiply that by 2

        processing_runs = 10
        processing_time_wash_trading_ms = timeit.timeit('agent.detect_scam(w3, wash_trading_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        processing_time_hard_rug_pull_ms = timeit.timeit('agent.detect_scam(w3, hard_rug_pull_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        processing_time_soft_rug_pull_ms = timeit.timeit('agent.detect_scam(w3, soft_rug_pull_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        processing_time_address_poisoning_ms = timeit.timeit('agent.detect_scam(w3, address_poisoning_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        processing_time_fraudulent_seaport_orders_ms = timeit.timeit('agent.detect_scam(w3, fraudulent_seaport_orders_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        processing_time_nip_ms = timeit.timeit('agent.detect_scam(w3, nip_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        processing_time_ice_phishing_ms = timeit.timeit('agent.detect_scam(w3, ice_phishing_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        processing_time_rake_token_ms = timeit.timeit('agent.detect_scam(w3, rake_token_alert_event, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        processing_time_avg = ((processing_time_wash_trading_ms * (500.0/80000) + processing_time_hard_rug_pull_ms * (300.0/80000) + processing_time_rake_token_ms * (10000.0/80000 +  processing_time_soft_rug_pull_ms * (1000.0/80000)) + 
                                processing_time_address_poisoning_ms * (60000.0/80000) + processing_time_fraudulent_seaport_orders_ms * (2000.0/80000) + processing_time_nip_ms * (1000.0/80000 +  processing_time_ice_phishing_ms * (5000.0/80000)))/8)

        assert (processing_time_avg/shards) < (1080*2), f"""processing time should be less than {(1080*2)}ms based on the existing sharding config, but is {(processing_time_avg/shards)} ms, 
            wash_trading: {processing_time_wash_trading_ms}, 
            hard_rug_pull: {processing_time_hard_rug_pull_ms}.
            rake_token: {processing_time_rake_token_ms} 
            soft_rug_pull: {processing_time_soft_rug_pull_ms} 
            nip: {processing_time_nip_ms} 
            fraudulent_seaport_orders: {processing_time_fraudulent_seaport_orders_ms} 
            address_poisoning: {processing_time_address_poisoning_ms} 
            ice_phishing: {processing_time_ice_phishing_ms}
            If not, this bot is unlikely to keep up with fast chains, like Polygon"""


    def test_perf_combination_alert(self):
        global w3 
        agent.initialize()
        shards = Utils.get_total_shards(1)
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        global alert_event_1
        alert_event_1 = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        bot_id = "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400"
        alert_id = "FUNDING-TORNADO-CASH"
        description = "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4 interacted with contract 0xcc5f573a93fcab719640f660173b8217664605d3"
        metadata = {}
        global alert_event_2
        alert_event_2 = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        processing_runs = 10
        alert_event_1_ms = timeit.timeit('agent.detect_scam(w3, alert_event_1, True)', number=processing_runs, globals=globals()) * 1000 / processing_runs
        alert_event_2_ms = timeit.timeit('agent.detect_scam(w3, alert_event_2, False)', number=processing_runs, globals=globals()) * 1000 / processing_runs
       
        processing_time_avg = ((alert_event_2_ms * (1.0/2) + alert_event_1_ms * (1.0/2))/2)

        assert (processing_time_avg/shards) < (1080*2), f"""processing time should be less than {(1080*2)}ms based on the existing sharding config, but is {(processing_time_avg/shards)} ms, 
            alert_event_1: {alert_event_1_ms} 
            alert_event_2: {alert_event_2_ms}
            If not, this bot is unlikely to keep up with fast chains, like Polygon"""
        

    def test_documentation(self):
        # read readme.md
        with open("README.md", "r") as f:
            readme = f.read()

            for bot_id, alert_id, alert_logic, alert_id_target in BASE_BOTS:
                found = False
                for line in readme.split("\n"):
                    if bot_id in line and alert_id in line and alert_logic in line:
                        found = True
            assert found, f"bot {bot_id} with alert {alert_id} and logic {alert_logic} not found in readme.md"
        

    def test_fp_mitigation_proper_chain_id(self):
        agent.clear_state()
        agent.initialize()

        findings = agent.emit_new_fp_finding(w3)

        df_fps = pd.read_csv("fp_list.csv")
        assert len(findings) == len(df_fps[df_fps['chain_id']==1]), "this should have triggered FP findings"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-FALSE-POSITIVE", "should be FP mitigation finding"
        assert finding.labels is not None, "labels should not be empty"


    def test_detect_wash_trading(self):
        agent.initialize()

        bot_id = "0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732"
        alert_id = "NFT-WASH-TRADE"
        description = "test Wash Trade on test."
        metadata = {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 2, "this should have triggered a finding for all two EOAs"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-WASH-TRADE", "should be wash trading finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"



    def test_detect_hard_rug_pull(self):
        agent.initialize()

        bot_id = "0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15"
        alert_id = "HARD-RUG-PULL-1"
        description = "0x8181bad152a10e7c750af35e44140512552a5cd9 deployed a token contract 0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9 that may result in a hard rug pull."
        metadata = {"attacker_deployer_address":"0x8181bad152a10e7c750af35e44140512552a5cd9","rugpull_techniques":"HIDDENTRANSFERREVERTS, HONEYPOT","token_contract_address":"0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-HARD-RUG-PULL", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"


    def test_detect_hard_rug_pull_no_repeat_finding(self):
        agent.initialize()

        bot_id = "0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15"
        alert_id = "HARD-RUG-PULL-1"
        description = "0x8181bad152a10e7c750af35e44140512552a5cd9 deployed a token contract 0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9 that may result in a hard rug pull."
        metadata = {"attacker_deployer_address":"0x8181bad152a10e7c750af35e44140512552a5cd9","rugpull_techniques":"HIDDENTRANSFERREVERTS, HONEYPOT","token_contract_address":"0xb68470e3E66862bbeC3E84A4f1993D1d100bc5A9"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-HARD-RUG-PULL", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"

        findings = agent.detect_scam(w3, alert_event, False)
        assert len(findings) == 0, "this should have not triggered another finding"

    def test_detect_rake_token(self):
        agent.initialize()

        bot_id = "0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11"
        alert_id = "RAKE-TOKEN-CONTRACT-1"
        description = "swapExactETHForTokensSupportingFeeOnTransferTokens function detected on Uniswap Router to take additional swap fee."
        metadata = {"actualValueReceived":"1.188051244910305019265053e+24","anomalyScore":"0.2226202661207779","attackerRakeTokenDeployer":"0xa0f80e637919e7aad4090408a63e0c8eb07dfa03","feeRecipient":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","from":"0x6c07456233f0e0fd03137d814aacf225f528068d","pairAddress":"0x2b25f23c31a490583ff55fb63cea459c098cc0e8","rakeTokenAddress":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","rakeTokenDeployTxHash":"0xec938601346b2ecac1bd82f7ce025037c09a3d817d00d723efa6fc5507bca5c2","rakedFee":"2.09656102042995003399715e+23","rakedFeePercentage":"15.00","totalAmountTransferred":"1.397707346953300022664768e+24"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-RAKE-TOKEN", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"
        assert finding.labels[0].entity == '0xa0f80e637919e7aad4090408a63e0c8eb07dfa03'
        assert finding.labels[0].label == 'scammer-eoa'
        found_contract = False
        for label in finding.labels:
            if label.entity == '0x440aeca896009f006eea3df4ba3a236ee8d57d36':
                assert label.label == 'scammer-contract'
                found_contract = True   
        assert found_contract, "should have found scammer contract"

    def test_detect_soft_rug_pull(self):
        agent.initialize()

        bot_id = "0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4"
        alert_id = "SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION"
        description = "Likely Soft rug pull has been detected"
        metadata = {"alert_hash":"0xd99ed20f397dbe53721e9a3424d0b87bcffb8df09fc2a9fea5748f81f3c7d324 && 0x0de8a4f6e1efff58a43cb20a81dd491e23b5eea32412a7b679129eb7b0638ea1","alert_id":"SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION","bot_id":"0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1","contractAddress":"\"0x27382445B936C1f362CbBC32E3d3fa5947220030\"","deployer":"\"0xa3fe18ced8d32ca601e3b4794856c85f6f56a176\"","token":"\"0xdd17532733f084ee4aa2de4a14993ef363843216\"","txHashes":"\"0x136af8104791a904614df3728a4bacf3bb79854db362e70f65e64a787ca23efa\""}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-SOFT-RUG-PULL", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"
        assert finding.labels[0].entity == '0xa3fe18ced8d32ca601e3b4794856c85f6f56a176'
        assert finding.labels[0].label == 'scammer-eoa'
        found_contract = False
        for label in finding.labels:
            if label.entity == '0xdd17532733f084ee4aa2de4a14993ef363843216':
                assert label.label == 'scammer-contract'
                found_contract = True   
        assert found_contract, "should have found scammer contract"


    def test_detect_address_poisoning(self):
        agent.initialize()

        bot_id = "0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502"
        alert_id = "ADDRESS-POISONING"
        description = "Possible address poisoning transaction."
        metadata = {"attackerAddresses":"0x1a1c0eda425a77fcf7ef4ba6ff1a5bf85e4fc168,0x55d398326f99059ff775485246999027b3197955","anomaly_score":"0.0023634453781512603","logs_length":"24","phishingContract":"0x81ff66ef2097c8c699bff5b7edcf849eb4f452ce","phishingEoa":"0xf6eb5da5850a1602d3d759395480179624cffe2c"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 3, "this should have triggered a finding for all three EOAs"
        finding = findings[0]
        assert "SCAM-DETECTOR-ADDRESS-POISON" in finding.alert_id, "should be address poison finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"



    def test_detect_native_ice_phishing(self):
        agent.initialize()

        bot_id = "0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0"
        alert_id = "NIP-1"
        description = "0x7cfb946f174807a4746658274763e4d7642233df sent funds to 0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183 with ClaimTokens() as input data"
        metadata = {"anomalyScore":"0.000002526532805344122","attacker":"0x63d8c1d3141a89c4dcad07d9d224bed7be8bb183","funcSig":"ClaimTokens()","victim":"0x7cfb946f174807a4746658274763e4d7642233df"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING", "should be soc eng native ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"

    
    def test_detect_ice_phishing_passthrough(self):
        agent.initialize()

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS"
        description = "0xFB4d3EB37bDe8FA4B52c60AAbE55B3Cd9908EC73 obtained transfer approval for 78 ERC-20 tokens by 195 accounts over period of 4 days."
        metadata = {"anomalyScore":"0.00012297740401709194","firstTxHash":"0x5840ac6991b6603de6b05a9da514e5b4d70b15f4bfa36175dd78388915d0b9a9","lastTxHash":"0xf841ffd55ee93da17dd1b017805904ce29c3127dee2db53872234f094d1ce2a0"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"



    def test_detect_fraudulent_seaport_orders(self):
        agent.initialize()

        bot_id = "0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac"
        alert_id = "nft-possible-phishing-transfer"
        description = "3 SewerPass id/s: 19445,25417,5996 sold on Opensea 🌊 for 0.01 ETH with a floor price of 2.5 ETH"
        metadata = {"interactedMarket": "opensea","transactionHash": "0x4fff109d9a6c030fce4de9426229a113524903f0babd6de11ee6c046d07226ff","toAddr": "0xBF96d79074b269F75c20BD9fa6DAed0773209EE7","fromAddr": "0x08395C15C21DC3534B1C3b1D4FA5264E5Bd7020C","initiator": "0xaefc35de05da370f121998b0e2e95698841de9b1","totalPrice": "0.001","avgItemPrice": "0.0002","contractAddress": "0xae99a698156ee8f8d07cbe7f271c31eeaac07087","floorPrice": "0.58","timestamp": "1671432035","floorPriceDiff": "-99.97%"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 2, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-FRAUDULENT-NFT-ORDER", "should be nft order finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.labels is not None, "labels should not be empty"

    def test_detect_alert_pos_finding_combiner_3_description(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400"
        alert_id = "FUNDING-TORNADO-CASH"
        description = "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4 interacted with contract 0xcc5f573a93fcab719640f660173b8217664605d3"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, False)
        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.metadata is not None, "metadata should not be empty"
        assert any(alert_event.alert_hash in str(value) for key, value in finding.metadata.items()), "metadata should contain alert hashes"
        assert any('TORNADO' in str(value) for key, value in finding.metadata.items()), "metadata should contain alert its"
        assert finding.labels is not None, "labels should not be empty"
        label = finding.labels[0]
        assert label.entity == "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4", "entity should be attacker address"
        assert label.label == "scammer-eoa", "entity should labeled as scam"
        assert label.confidence == 0.62, "entity should labeled with 0.62 confidence"
        assert label.metadata['alert_ids'] == "SCAM-DETECTOR-ICE-PHISHING", "entity should labeled as ice phishing"
        assert label.metadata['chain_id'] == 1, "entity should labeled for chain_id 1"


    def test_detect_alert_pos_finding_combiner_3_metadata(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))


        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = agent.detect_scam(w3, alert_event, True)
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895"
        alert_id = "AE-MALICIOUS-ADDR"
        description = "0x21e13f16838e2fe78056f5fd50251ffd6e7098b4 obtained"
        metadata = {"amount":"0","from":"0x4f07bb5b0c204da3d1c7a35dab23114ac2145980","malicious_details":"[{'index': '609', 'id': '1ae52e', 'name': 'moonbirdsraffle.xyz', 'type': 'scam', 'url': 'https://moonbirdsraffle.xyz', 'hostname': 'moonbirdsraffle.xyz', 'featured': '0', 'path': '/*', 'category': 'Phishing', 'subcategory': 'Moonbirds', 'description': 'Fake Moonbirds NFT site phishing for funds', 'reporter': 'CryptoScamDB', 'severity': '1', 'updated': '1.65635E+12', 'address': '0x21e13f16838e2fe78056f5fd50251ffd6e7098b4'}]","to":"0x335eeef8e93a7a757d9e7912044d9cd264e2b2d8"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, False)
        assert len(findings) == 1, "this should have not triggered a finding"

    def test_detect_alert_pos_finding_combiner_3_tx_to(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0x21E13f16838e2fe78056f5fd50251ffd6e7098b4 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = agent.detect_scam(w3, alert_event, True)
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"
        alert_id = "forta-text-messages-possible-hack"
        description = "description obtained"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, False)
        assert len(findings) == 1, "this should have not triggered a finding"

    def test_detect_alert_no_finding_large_tx_count(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0xdec08cb92a506B88411da9Ba290f3694BE223c26 obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = agent.detect_scam(w3, alert_event, True)
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"
        alert_id = "forta-text-messages-possible-hack"
        description = "description obtained"
        metadata = {}
        transaction_hash = "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02618"
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, transaction_hash=transaction_hash)

        findings = agent.detect_scam(w3, alert_event, False)
        assert len(findings) == 0, "this should have not triggered a finding as the EOA has too many txs"

    def test_detect_alert_pos_nofinding(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99"
        alert_id = "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH"
        description = "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4 funded by TC"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = agent.detect_scam(w3, alert_event, True)
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400"
        alert_id = "FUNDING-TORNADO-CASH"
        description = "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4 funded by TC"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = agent.detect_scam(w3, alert_event, False)
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2"
        alert_id = "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH"
        description = "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4 laundered funds"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = agent.detect_scam(w3, alert_event, False)
        assert len(findings) == 0, "this should have not triggered a finding"


    def test_detect_alert_pos_finding_combiner_with_cluster(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9"
        alert_id = "ENTITY-CLUSTER"
        description = "Entity of size 2 has been identified. Transaction from 0x7a2a13c269b3b908ca5599956a248c5789cc953f created this entity."
        metadata = {"entityAddresses":"0x7A2a13C269b3B908Ca5599956A248c5789Cc953f,0x91C1B58F24F5901276b1F2CfD197a5B73e31F96E"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = agent.detect_scam(w3, alert_event, True)
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL"
        description = "0x7A2a13C269b3B908Ca5599956A248c5789Cc953f obtained transfer approval for 3 assets by 6 accounts over period of 2 days."
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)
       
        findings = agent.detect_scam(w3, alert_event, False)
        assert len(findings) == 0, "this should have not triggered a finding"

        bot_id = "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4"
        alert_id = "forta-text-messages-possible-hack"
        description = "description"
        transaction_hash = "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a026aa"
        metadata = {}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, transaction_hash=transaction_hash)
       
        findings = agent.detect_scam(w3, alert_event, False)
        assert len(findings) == 1, "this should have triggered a finding"


    def test_detect_alert_similar_contract(self):
        agent.initialize()
        
        bot_id = "0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560"
        alert_id = "NEW-SCAMMER-CONTRACT-CODE-HASH"
        description = "0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0 created contract 0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2. It is similar to scam contract 0xe22536ac6f6a20dbb283e7f61a880993eab63313 created by 0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e."
        metadata = {"alertHash":"0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016","newScammerContractAddress":"0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2","newScammerEoa":"0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0","scammerContractAddress":"0xe22536ac6f6a20dbb283e7f61a880993eab63313","scammerEoa":"0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e","similarityHash":"68e6432db785f93986a9d49b19077067f8b694612f2bc1e8ef5cd38af2c8727e","similarityScore":"0.9847575306892395"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "SCAM-DETECTOR-SIMILAR-CONTRACT"
        assert findings[0].metadata['scammer_address'] == "0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0", "metadata should not be empty"
        assert findings[0].metadata['scammer_contract_address'] == "0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2", "metadata should not be empty"
        assert findings[0].metadata['existing_scammer_address'] == "0xc1015eb4d9aa4f77d79cf04825cbfb7fc04e232e", "metadata should not be empty"
        assert findings[0].metadata['existing_scammer_contract_address'] == "0xe22536ac6f6a20dbb283e7f61a880993eab63313", "metadata should not be empty"
        assert findings[0].metadata['similarity_score'] == "0.9847575306892395", "metadata should not be empty"
        assert findings[0].metadata['involved_alert_id_1'] == "SCAM-DETECTOR-ADDRESS-POISONER", "metadata should not be empty"
        assert findings[0].metadata['involved_alert_hash_1'] == "0x92f0e1c5f9677a3ea2903047641213ba62e5a00d62f363efc1a85cd1e184e016", "metadata should not be empty"

        assert findings[0].labels is not None, "labels should not be empty"
        label = findings[0].labels[0]
        assert label.entity == "0x7e6b6f2be1bb8d2e1d5fcefa2d6df86b6e03b8d0", "entity should be attacker address"
        assert label.label == "scammer-eoa", "entity should labeled as scam"
        assert label.confidence == 0.4, "entity should labeled with 0.7 confidence"
        assert label.metadata['alert_ids'] == "SCAM-DETECTOR-SIMILAR-CONTRACT", "entity should labeled as similar contract"
        assert label.metadata['chain_id'] == 1, "entity should labeled for chain_id 1"

        label = findings[0].labels[1]
        assert label.entity == "0x75577bd21803a13d6ec3e0d784f84e0e7e31cbd2", "entity should be attacker address"
        assert label.label == "scammer-contract", "entity should labeled as scam"
        assert label.confidence == 0.4, "entity should labeled with 0.7 confidence"
        assert label.metadata['alert_ids'] == "SCAM-DETECTOR-SIMILAR-CONTRACT", "entity should labeled as similar contract"
        assert label.metadata['chain_id'] == 1, "entity should labeled for chain_id 1"

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
