import time
import timeit
import os
import io
import random
import base64
import json
import gnupg
from datetime import datetime
import pandas as pd
import numpy as np
from forta_agent import create_transaction_event, create_alert_event, FindingSeverity, AlertEvent, Label, EntityType, Finding, FindingType
import requests
import agent
from unittest.mock import patch

from constants import BASE_BOTS, MODEL_ALERT_THRESHOLD_LOOSE, MODEL_FEATURES
from web3_mock import CONTRACT, EOA_ADDRESS_SMALL_TX, Web3Mock, EOA_ADDRESS_LARGE_TX, CONTRACT2, SCAM_CONTRACT_DEPLOYER
from web3_errormock import Web3ErrorMock
from forta_explorer_mock import FortaExplorerMock
from blockchain_indexer_mock import BlockChainIndexerMock
from utils import Utils



w3 = Web3Mock()
w3error = Web3ErrorMock()
forta_explorer = FortaExplorerMock()
block_chain_indexer = BlockChainIndexerMock()


class TestScamDetector:

    @staticmethod
    def encrypt_alert_event(alert_event: AlertEvent):
        # test key
        public_key = """-----BEGIN PGP PUBLIC KEY BLOCK-----

            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
            =QBhA
            -----END PGP PUBLIC KEY BLOCK-----
            """
        gpg = gnupg.GPG(gnupghome='.')
        import_result = gpg.import_keys(public_key)
        fp = ""
        for fingerprint in import_result.fingerprints:
            fp = fingerprint
            gpg.trust_keys(fingerprint, 'TRUST_ULTIMATE')


        finding = Finding({
            'name': alert_event.alert.name,
            'description': alert_event.alert.description,
            'alert_id': alert_event.alert.alert_id,
            'severity': FindingSeverity(alert_event.alert.severity),
            'type': FindingType(alert_event.alert.finding_type),
            'metadata': alert_event.alert.metadata,
            'labels': alert_event.alert.labels,
        })
        finding_json = finding.toJson()
        encrypted_finding = gpg.encrypt(finding_json, fp)
        encrypted_finding_ascii = str(encrypted_finding)

        alert_event.alert.name = "omitted"
        alert_event.alert.description = "omitted"
        alert_event.alert.alert_id = "omitted"
        alert_event.alert.severity = FindingSeverity.Unknown
        alert_event.alert.finding_type = FindingType.Unknown
        alert_event.alert.metadata = { 'data': encrypted_finding_ascii }
        alert_event.alert.labels = []
        return alert_event
        

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
                   "chainId": 1,
                   "severity": 2,
                   "findingType": 2,  
                   "createdAt": ts,
                   "source": {"bot": {'id': bot_id}, "block": {"chainId": 1, 'number': 5},  'transactionHash': transaction_hash},
                   "metadata": metadata,
                   "labels": labels_tmp
                  }
                }
        
        return create_alert_event(alert)
    
    @staticmethod
    def filter_findings(findings: list, logic: str) -> list:
        findings_result = []
        for finding in findings:
            if 'logic' in finding.metadata.keys() and finding.metadata['logic'] == logic:
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

    def test_detect_wash_trading(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8732dbb3858d65844d940f5de3705b4161c05258bdfedf1ff5afb6683e1274e5"
        alert_id = "NFT-WASH-TRADE"
        description = "test Wash Trade on test."
        metadata = {"buyerWallet":"0xa53496B67eec749ac41B4666d63228A0fb0409cf","sellerWallet":"0xD73e0DEf01246b650D8a367A4b209bE59C8bE8aB","anomalyScore":"21.428571428571427% of total trades observed for test are possible wash trades","collectionContract":"test","collectionName":"test","exchangeContract":"test","exchangeName":"test","token":"Wash Traded NFT Token ID: 666688"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 2, "this should have triggered a finding for all two EOAs"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-WASH-TRADE", "should be wash trading finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"



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
        assert len(finding.labels) > 0, "labels should not be empty"



    def test_ice_phishing_url(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534"
        alert_id = "Ice-phishing-web"
        description = "description"
        metadata = {'scammer': '', 'URL': 'withdraw-llido.com', 'detail': 'https://urlscan.io/result/1870a15b-2b37-4980-9968-ac8a01e083f9/', 'transaction': ''}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for the URL"
        finding = findings[0]
        assert finding.description == "URL withdraw-llido.com likely involved in a scam (SCAM-DETECTOR-ICE-PHISHING, passthrough)"
        assert finding.alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"

        assert len(finding.labels) == 1, "should have one label"
        assert finding.labels[0].entity_type == EntityType.Url, "should be URL label"
        assert finding.labels[0].entity == "withdraw-llido.com"
        assert finding.labels[0].metadata['chain_id'] == -1, "should be chain agnostic given we only have the URL and no scammer or tx"
        
        assert finding.labels[0].metadata['source_url_scan_url'] == 'https://urlscan.io/result/1870a15b-2b37-4980-9968-ac8a01e083f9/'


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
        assert len(finding.labels) > 0, "labels should not be empty"

    

    def test_detect_gas_minting(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x715c40c11a3e24f3f21c3e2db1c109bba358ccfcbceada84ee1e0f4dba4410e7"
        alert_id = "GAS-ANOMALOUS-LARGE-CONSUMPTION"
        description = "Suspicious function with anomalous gas detected: 14246778"
        metadata = {"contractAddress":"\"0xe5e6138e3a6b6ef85b9d2bad287138715ebfa20b\"","deployer":"\"0x32e9f1638a05967c8a30fb1e9febd27c38f29f80\"","function":"\"MethodId is 0x095ea7b3\"","mean":"\"77781.69054054054054054056\"","threshold":"\"6537343.74973840585266180776\"","value":"\"14246778\""}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-GAS-MINTING", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 1, "labels should not be empty"


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
        assert len(finding.labels) > 0, "labels should not be empty"

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
        assert len(finding.labels) > 0, "labels should not be empty"
        assert finding.labels[0].entity == '0x8181bad152a10e7c750af35e44140512552a5cd9'

        bot_id = "0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11"
        alert_id = "RAKE-TOKEN-CONTRACT-1"
        description = "swapExactETHForTokensSupportingFeeOnTransferTokens function detected on Uniswap Router to take additional swap fee."
        metadata = {"actualValueReceived":"1.188051244910305019265053e+24","anomalyScore":"0.2226202661207779","attackerRakeTokenDeployer":"0x8181bad152a10e7c750af35e44140512552a5cd9","feeRecipient":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","from":"0x6c07456233f0e0fd03137d814aacf225f528068d","pairAddress":"0x2b25f23c31a490583ff55fb63cea459c098cc0e8","rakeTokenAddress":"0x440aeca896009f006eea3df4ba3a236ee8d57d36","rakeTokenDeployTxHash":"0xec938601346b2ecac1bd82f7ce025037c09a3d817d00d723efa6fc5507bca5c2","rakedFee":"2.09656102042995003399715e+23","rakedFeePercentage":"15.00","totalAmountTransferred":"1.397707346953300022664768e+24"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=False),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA for the different alert_id"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-RAKE-TOKEN", "should be hard rug pull finding"
        assert len(finding.labels) > 0, "labels should not be empty"
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

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-RAKE-TOKEN", "should be hard rug pull finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"
        assert finding.labels[0].entity == '0xa0f80e637919e7aad4090408a63e0c8eb07dfa03'
        assert finding.labels[0].label == 'scammer'
        found_contract = False
        for label in finding.labels:
            if label.entity == '0x440aeca896009f006eea3df4ba3a236ee8d57d36':
                assert label.label == 'scammer'
                found_contract = True   
        assert found_contract, "should have found scammer contract"


    def test_detect_chainpatrol_phishing_url(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x42dbb60aa8059dd395df9f66230f63852856f7fdd0d6d3fc55b708f8f84a3f47"
        alert_id = "CHAINPATROL-SCAM-ASSET"
        description = "ChainPatrol detected scam: free-mantle.foundation-claim.com"
        metadata = {"reason":"reported","reportId":"7655","report_url":"https://app.chainpatrol.io/reports/7655","status":"BLOCKED","type":"URL","updatedAt":"2023-10-09T00:53:48.625Z","Url":"free-mantle.foundation-claim.com"}
        labels = []
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, labels)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"
        assert finding.labels[0].entity_type == EntityType.Url, "should be URL label"
        assert finding.labels[0].entity == 'free-mantle.foundation-claim.com'
        assert finding.labels[0].label == 'scammer'
        assert finding.labels[0].metadata['chain_id'] == -1, "should be chain agnostic given we only have the URL and no scammer or tx"
        assert finding.labels[0].metadata['source_url_scan_url'] == 'https://app.chainpatrol.io/reports/7655'


    def test_detect_blocksec_phishing_unencrypted(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534"
        alert_id = "Ice-phishing"
        description = "Token Transfer Phishing Alert: Scammer (0x0000..9000) profited $168.35931259760338 from phishing. In this transaction, the token (QNT) of the user (0xc1c83d16121bad48ce3e431edd031e741aa6b1e6) was transferred to the address (0x0000553f880ffa3728b290e04e819053a3590000), and the target address was labeled as a phishing address. We believe the user was deceived into a token transfer transaction."
        metadata = {"hash":"0xb5f699cc4d3dba99eba23268aebbcd11384dd33a02f447630116ae4276969f9e","scammer":"0x0000553f880ffa3728b290e04e819053a3590000","victim":"0xc1c83d16121bad48ce3e431edd031e741aa6b1e6"}
        label = {"entity": "0x0000553f880ffa3728b290e04e819053a3590000","entityType": "ADDRESS","label": "phish","metadata": {},"confidence": 1}
        labels = [ label ]
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, labels)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"
        assert finding.labels[0].entity == '0x0000553f880ffa3728b290e04e819053a3590000'
        assert finding.labels[0].label == 'scammer'
        found_contract = False
        for label in finding.labels:
            if label.entity == '0x3eaabef289fdd9072c3ecae94d406c21de881247':
                assert label.label == 'scammer'
                found_contract = True   
        assert found_contract, "should have found scammer contract"

    def test_detect_social_eng_contract_creation(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0xee275019391109f9ce0de16b78e835c261af1118afeb1a1048a08ccbf67c3ea8"
        alert_id = "SOCIAL-ENG-CONTRACT-CREATION"
        description = "0x7c6aef35d0b7730315124ce08ffbddbaaa7f2ff8 created contract 0x0000e30c782ee0a845038e2324592f8f9a2b0000 impersonating 0x0000daf60a1becf1bd617c584dea964455890000."
        metadata = {"anomaly_score":"0.0006531678641410843","impersonated_contract":"0x0000daf60a1becf1bd617c584dea964455890000"}
        label1 = {"entity": "0x7c6aef35d0b7730315124ce08ffbddbaaa7f2ff8","entityType": "ADDRESS","label": "attacker","metadata": {},"confidence": 1}
        label2 = {"entity": "0x0000daf60a1becf1bd617c584dea964455890000","entityType": "ADDRESS","label": "attacker_contract","metadata": {},"confidence": 1}
        labels = [ label1, label2 ]
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, labels)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-UNKNOWN", "should be ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"
        assert finding.labels[0].entity == '0x7c6aef35d0b7730315124ce08ffbddbaaa7f2ff8'
        assert finding.labels[0].label == 'scammer'
        found_contract = False
        for label in finding.labels:
            if label.entity == '0x0000e30c782ee0a845038e2324592f8f9a2b0000':
                assert label.label == 'scammer'
                found_contract = True   
        assert found_contract, "should have found scammer contract"

    def test_detect_blocksec_phishing_encrypted(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534"
        alert_id = "Ice-phishing-web"
        description = "Token Transfer Phishing Alert: Scammer (0x0000..9000) profited $168.35931259760338 from phishing. In this transaction, the token (QNT) of the user (0xc1c83d16121bad48ce3e431edd031e741aa6b1e6) was transferred to the address (0x0000553f880ffa3728b290e04e819053a3590000), and the target address was labeled as a phishing address. We believe the user was deceived into a token transfer transaction."
        metadata = {"hash":"0xb5f699cc4d3dba99eba23268aebbcd11384dd33a02f447630116ae4276969f9e","scammer":"0x0000553f880ffa3728b290e04e819053a3590000","victim":"0xc1c83d16121bad48ce3e431edd031e741aa6b1e6"}
        label = {"entity": "0x0000553f880ffa3728b290e04e819053a3590000","entityType": "ADDRESS","label": "phish","metadata": {},"confidence": 1}
        labels = [ label ]
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, labels)

        encrypted_alert_event = TestScamDetector.encrypt_alert_event(alert_event)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, encrypted_alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"
        assert finding.labels[0].entity == '0x0000553f880ffa3728b290e04e819053a3590000'
        assert finding.labels[0].label == 'scammer'
        found_contract = False
        for label in finding.labels:
            if label.entity == '0x3eaabef289fdd9072c3ecae94d406c21de881247':
                assert label.label == 'scammer'
                found_contract = True   
        assert found_contract, "should have found scammer contract"


    def test_detect_blocksec_phishing_drainer_encrypted(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534"
        alert_id = "Phishing-drainer"
        description = "Drainer report."
        metadata = {'scammer': 'Inferno Drainer Affiliate Account', 'transaction': '0xaf300549d642b31bc2a1d6cf1dbf31213be7634f5bfb5d5ada45b1e6d7bb1f48'}
        label = {"entity": "0xfaee4d9ce515c83cdca2e4a7365e7ecbbe74d29d","entityType": "ADDRESS","label": "affiliate","metadata": {"drainer-name": "Inferno Drainer"},"confidence": 1}
        labels = [ label ]
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, labels)

        encrypted_alert_event = TestScamDetector.encrypt_alert_event(alert_event)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, encrypted_alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding for the affiliate EOA"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be ice phishing finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert finding.metadata['attribution'] == 'Inferno Drainer', "should have drainer name in metadata"
        assert len(finding.labels) > 0, "labels should not be empty"
        assert finding.labels[0].entity == '0xfaee4d9ce515c83cdca2e4a7365e7ecbbe74d29d'
        assert finding.labels[0].label == 'scammer'
        assert finding.labels[0].metadata['attribution'] == 'Inferno Drainer'
      

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
        assert len(finding.labels) > 0, "labels should not be empty"
        assert finding.labels[0].entity == '0xa3fe18ced8d32ca601e3b4794856c85f6f56a176'
        assert finding.labels[0].label == 'scammer'
        found_contract = False
        for label in finding.labels:
            if label.entity == '0xdd17532733f084ee4aa2de4a14993ef363843216':
                assert label.label == 'scammer'
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
        assert len(finding.labels) > 0, "labels should not be empty"



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
        assert len(finding.labels) > 0, "labels should not be empty"

    
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
        assert len(finding.labels) > 0, "labels should not be empty"



    def test_detect_ice_phishing_pig_butchering(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"
        alert_id = "ICE-PHISHING-PIG-BUTCHERING"
        description = "0xdA453CA63F802EE1267f1bA3f9c0120b327B3A7C received funds through a pig butchering attack"
        metadata = {"anomalyScore":"0.00041909736904142703","initiator1":"0xE9EE9F6B8d09469E7f54E1B23aeA034125c66bfB","initiator2":"0xcEc1214a5269fC5A3f75ce81dA8ad6CA60B9dFB2","receiver":"0xdA453CA63F802EE1267f1bA3f9c0120b327B3A7C","victim1":"0x0E7a79Fa499b33cEf30704202ae947A47be09a8C","victim2":"0x102f51037699597B95e9f846451C762b7eF3DF78","victim3":"0xd546B23A7A4685aDCc6a3745419600D1094B1887","victim4":"0x66e7ACA614c13D94F060928bF77526cac82142E9"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-PIG-BUTCHERING", "should be pig butchering finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"


    def test_detect_fraudulent_seaport_orders(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x15e9b3cd277d3be1fcfd5e23d61b3496026d8c3d9c98ef47a48e37b3c216ab9f"
        alert_id = "nft-phishing-sale"
        description = "3 SewerPass id/s: 19445,25417,5996 sold on Opensea 🌊 for 0.01 ETH with a floor price of 2.5 ETH"
        metadata = {"interactedMarket": "opensea","transactionHash": "0x4fff109d9a6c030fce4de9426229a113524903f0babd6de11ee6c046d07226ff","toAddr": "0xBF96d79074b269F75c20BD9fa6DAed0773209EE7","fromAddr": "0x08395C15C21DC3534B1C3b1D4FA5264E5Bd7020C","initiator": "0xaefc35de05da370f121998b0e2e95698841de9b1","totalPrice": "0.001","avgItemPrice": "0.0002","contractAddress": "0xae99a698156ee8f8d07cbe7f271c31eeaac07087","floorPrice": "0.58","timestamp": "1671432035","floorPriceDiff": "-99.97%"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 2, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-FRAUDULENT-NFT-ORDER", "should be nft order finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"

    # 11/22/2023 - disabled as we havent been able to ship this for while now
    # def test_detect_private_key_compromise(self):
    #     agent.initialize()
    #     agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

    #     bot_id = "0x6ec42b92a54db0e533575e4ebda287b7d8ad628b14a2268398fd4b794074ea03"
    #     alert_id = "PKC-3"
    #     description = "0x006a176a0092b19ad0438919b08a0ed317a2a9b5 transferred funds to 0xdcde9a1d3a0357fa3db6ae14aacb188155362974 and has been inactive for a week"
    #     metadata = {"anomalyScore":"0.00011111934217349434","attacker":"0xdcde9a1d3a0357fa3db6ae14aacb188155362974","transferredAsset":"MATIC","txHash":"0xd39f161892b9cb184b9daa44d2d5ce4a75ab3133275d5f12a4a2b5eed56b6f41","victims":"0x006a176a0092b19ad0438919b08a0ed317a2a9b5"}
    #     alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

    #     findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

    #     assert len(findings) == 1, "this should have triggered a finding"
    #     finding = findings[0]
    #     assert finding.alert_id == "SCAM-DETECTOR-PRIVATE-KEY-COMPROMISE", "should be private key compromise finding"
    #     assert finding.metadata is not None, "metadata should not be empty"
    #     assert len(finding.labels) > 0, "labels should not be empty"


    def test_detect_impersonating_token(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127"
        alert_id = "IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR"
        description = "0x0cfeaed6f106154153325342d509b3a61b94d68c deployed an impersonating token contract at 0xfbd4f5ce3824af29fcb9e90ccb239f1761670606. It impersonates token BTC (Bitcoin) at 0x05f774f2eca50291a0407ca881f6405d84ea005b"
        metadata = {"anomalyScore":"0.008463572974272662","newTokenContract":"0xfbd4f5ce3824af29fcb9e90ccb239f1761670606","newTokenDeployer":"0x0cfeaed6f106154153325342d509b3a61b94d68c","newTokenName":"Bitcoin","newTokenSymbol":"BTC","oldTokenContract":"0x05f774f2eca50291a0407ca881f6405d84ea005b","oldTokenDeployer":"0x5abf98eb769114e43b1c87413f2a93a384d2e905","oldTokenName":"Bitcoin","oldTokenSymbol":"BTC"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-IMPERSONATING-TOKEN", "should be impersonating token finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"


    def test_detect_spam_phish_token(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0xd45f7183783f5893f4b8e187746eaf7294f73a3bb966500d237bd0d5978673fa"
        alert_id = "PHISHING-TOKEN-NEW"
        description = "The ERC-1155 token 2000$ USDC (Voucher) 0xe5e6138e3a6b6ef85b9d2bad287138715ebfa20b shows signs of phishing behavior. Confidence: 0.9. Potential phishing URLs: https://circleusd.co/."
        metadata = {"analysis":"{\"name\":\"2000$ USDC\",\"symbol\":\"Voucher\",\"urls\":[\"https://circleusd.co/.\"],\"descriptionByTokenId\":{\"0\":\"Congratulations! You can exchange this NFT voucher for $2000 USDC at the official site: https://circleusd.co/.\"}}","confidence":"0.8999999999999999","tokenAddress":"0xe5e6138e3a6b6ef85b9d2bad287138715ebfa20b","tokenDeployer":"0x32e9f1638a05967c8a30fb1e9febd27c38f29f80","tokenStandard":"ERC-1155","urls":"[\"https://circleusd.co/.\"]"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be impersonating token finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"
        assert len(finding.labels) == 3, "should have 3 labels; for deployer, contract and url"


    def test_detect_scam_notifier(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x112eaa6e9d705efb187be0073596e1d149a887a88660bd5491eece44742e738e"
        alert_id = "SCAM-NOTIFIER-EOA"
        description = "0x72dd58002e6d17a3ec18b9ae3460449c51d619ac was flagged as a scam by 0xba6e11347856c79797af6b2eac93a8145746b4f9 🛑scam-warning🛑.eth"
        metadata = {"message":"HARD SCAM DETECTED\n\nVerify: https://t.me/iTokenEthereum/533110\nWarning issued by iToken - a cloud based token spotter & scam detector.","notifier_eoa":"0xba6e11347856c79797af6b2eac93a8145746b4f9","notifier_name":"🛑scam-warning🛑.eth","scammer_eoa":"0x72dd58002e6d17a3ec18b9ae3460449c51d619ac"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-UNKNOWN", "should be scammer unknown finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"


    def test_detect_impersonating_token_with_error(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127"
        alert_id = "IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR"
        description = "0x0cfeaed6f106154153325342d509b3a61b94d68c deployed an impersonating token contract at 0xfbd4f5ce3824af29fcb9e90ccb239f1761670606. It impersonates token BTC (Bitcoin) at 0x05f774f2eca50291a0407ca881f6405d84ea005b"
        metadata = {"anomalyScore":"0.008463572974272662","newTokenContract":"0xfbd4f5ce3824af29fcb9e90ccb239f1761670606","newTokenDeployer":"0x0cfeaed6f106154153325342d509b3a61b94d68c","newTokenName":"Bitcoin","newTokenSymbol":"BTC","oldTokenContract":"0x05f774f2eca50291a0407ca881f6405d84ea005b","oldTokenDeployer":"0x5abf98eb769114e43b1c87413f2a93a384d2e905","oldTokenName":"Bitcoin","oldTokenSymbol":"BTC"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = TestScamDetector.filter_findings(agent.detect_scam(w3error, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding"
        assert Utils.ERROR_CACHE.len() > 0, "error cache should not be empty given w3error logged an error"

    def test_detect_twitter_bot_scammer(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        bot_id = "0x154da7913f0d42dc50b5007fc4950ac0ab1f399023a0703784fd461d874100c5"
        alert_id = "FORTA-1"
        description = "Address 0x9fcf3f94ed5673f414907e381faaa2b014319eb3 was mentioned in a Tweet"
        metadata = {"accountFrom":"@realScamSniffer","dateTweeted":"03/08/2024","tweetURL":"https://twitter.com/realScamSniffer/status/1766104252185989239","twitterMentionedAccount":"0x9fcf3f94ed5673f414907e381faaa2b014319eb3","tweetText":"victim: 0x02fbadf4f6587885c7db75c65d13cf5fed2d246e scammer: 0x9fcf3f94ed5673f414907e381faaa2b014319eb3 https://t.co/uZL6Gy9jHx"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)


        findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

        assert len(findings) == 1, "this should have triggered a finding"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-UNKNOWN", "should be impersonating token finding"
        assert finding.metadata is not None, "metadata should not be empty"
        assert len(finding.labels) > 0, "labels should not be empty"

    def test_detect_alert_similar_contract(self):
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        # Read the content of package.json and store the original "name" field
        original_name = ""
        with open("package.json", "r") as package_file:
            package_data = json.load(package_file)
            original_name = package_data["name"]

        # Modify the "name" field to "beta" (as alt doesn't return labels for the test)
        package_data["name"] = "beta"
        with open("package.json", "w") as package_file:
            json.dump(package_data, package_file, indent=2)
        
        bot_id = "0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560"
        alert_id = "NEW-SCAMMER-CONTRACT-CODE-HASH"
        description = "0xd359b4058cfbc9a5ef2889bc484cbbffbe3fa254f6f36845be6a4f5618531bd5 (NEW-SCAMMER-CONTRACT-CODE-HASH)"

        metadata = {"alert_hash":"0xcfc5f89ac8c801901724621470fb7e3efec1b0cb5e1af625b82d587b788cdc86","new_scammer_contract_address":"0xfe551e214563283c8ab5df967d7d69f630b64079","new_scammer_eoa":"0xa4f58353711f9f29b483fe41be8f0dcc893d9f8a","scammer_contract_address":"0x200c5fa46720e40c375dd276a816da905b19081e","scammer_eoa":"0x43cf4c4759ebe43aa6e21e13ece8546dcfcb728c","similarity_hash":"20d794469ef5c3f5937d8b2ad1505e57a97b6fa0205b9fba965d71e9a4f66ea6","similarity_score":"0.9768354296684265"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings = agent.detect_scam(w3, alert_event, True)

        # Revert the "name" field back to its original value
        package_data["name"] = original_name
        with open("package.json", "w") as package_file:
            json.dump(package_data, package_file, indent=2)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "SCAM-DETECTOR-SIMILAR-CONTRACT"
        assert findings[0].metadata['scammer_address'] == "0xa4f58353711f9f29b483fe41be8f0dcc893d9f8a", "metadata should not be empty"
        assert findings[0].metadata['scammer_contract_address'] == "0xfe551e214563283c8ab5df967d7d69f630b64079", "metadata should not be empty"
        assert findings[0].metadata['existing_scammer_address'] == "0x43cf4c4759ebe43aa6e21e13ece8546dcfcb728c", "metadata should not be empty"
        assert findings[0].metadata['existing_scammer_contract_address'] == "0x200c5fa46720e40c375dd276a816da905b19081e", "metadata should not be empty"
        assert findings[0].metadata['similarity_score'] == "0.9768354296684265", "metadata should not be empty"
        assert findings[0].metadata['involved_threat_categories'] == "soft-rug-pull", "metadata should not be empty"
        assert findings[0].metadata['involved_alert_hash_1'] == "0xcfc5f89ac8c801901724621470fb7e3efec1b0cb5e1af625b82d587b788cdc86", "metadata should not be empty"

        assert findings[0].labels is not None, "labels should not be empty"
        label = findings[0].labels[0]
        assert label.entity == "0xa4f58353711f9f29b483fe41be8f0dcc893d9f8a", "entity should be attacker address"
        assert label.label == "scammer", "entity should labeled as scam"
        assert label.confidence == Utils.get_confidence_value('similar-contract'), "entity should labeled with 0.7 confidence"

        label = findings[0].labels[1]
        assert label.entity == "0xfe551e214563283c8ab5df967d7d69f630b64079", "entity should be attacker address"
        assert label.label == "scammer", "entity should labeled as scam"
        assert label.confidence == Utils.get_confidence_value('similar-contract'), "entity should labeled with 0.7 confidence"

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


    def test_scammer_contract_deployment(self):
        agent.clear_state()
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': '0x07f4d1733c85650234a94e884b0d4764c399ab5c', # BNB Chain
                'nonce': 73,
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
        assert findings[0].metadata["scammer_contract_address"] == "0xa5b7bfe4e73b5b6f9c7462b28ac3b326eda9e3ff".lower(), "wrong scammer_contract"

    #TODO once deployed and those labels with new format coming in
    def test_scammer_contract_deployment_indirect(self):
        agent.clear_state()
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': "0x07f4d1733c85650234a94e884b0d4764c399ab5c",
                'to': "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
                'nonce': 0,
            },
            'block': {
                'number': 0
            },
            'logs': [
                    {'address': "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f".lower(),
                    'topics': ["0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9","0x00000000000000000000000016110b84fbc144f3879cbd4f201e724c79fbb52d", "0x000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"],
                    'data': f"0x00000000000000000000000080a8b0ced96a8eacf0bd6c08c121aaf1a6e2b62000000000000000000000000000000000000000000000000000000000000322c6"
                 }
            ],
            'receipt': {
                'logs': []
            }
        })
        findings = agent.detect_scammer_contract_creation(w3, tx_event)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"
        assert findings[0].metadata["scammer_contract_address"] == "0x80a8b0cEd96a8EaCF0bd6C08C121Aaf1a6E2B620".lower(), "wrong scammer_contract"

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
                  "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL": 1
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

        assert len(all_findings) == 1
        assert all_findings[0].alert_id == "SCAM-DETECTOR-ICE-PHISHING", "should be SCAM-DETECTOR-ICE-PHISHING"
        assert all_findings[0].severity == FindingSeverity.Critical, "should be Critical"

        assert all_findings[0].labels is not None, "labels should not be empty"
        label = all_findings[0].labels[0]
        assert "ml" == label.metadata['logic']
        assert label.confidence > 0.86 and label.confidence < 0.87, "confidence should be between 0.86 and 0.87"
        



    def test_get_scam_detector_alert_ids(self):
        alert_list = [("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC20-SCAM-PERMIT", "hash1"), ("0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799", "ATTACK-DETECTOR-1", "hash2"), ("0xdba64bc69511d102162914ef52441275e651f817e297276966be16aeffe013b0", "UMBRA-RECEIVE", "hash3")]
        expected_result = {"SCAM-DETECTOR-ICE-PHISHING", "SCAM-DETECTOR-1"}

        actual = agent.get_scam_detector_alert_ids(alert_list)
        assert actual == expected_result

    # Test disabled until the update to the model
    # def test_subscription_model_features(self):
    #     missing_subscription_str = ""
        
    #     for feature in MODEL_FEATURES:
    #         botId1 = feature.split("_")[0]
    #         alertId1 = feature[len(botId1) + 1:]
    #         if alertId1 == "count" or alertId1 == "uniqalertid_count":
    #             continue

    #         found = False
    #         for botId, alertId, alert_logic, target_alert_id in BASE_BOTS:
    #             if botId == botId1 and alertId == alertId1:
    #                 found = True

    #         if not found:
    #             missing_subscription_str += f'("{botId1}", "{alertId1}", "Combination", ""),\r\n'
            
    #     print(missing_subscription_str) 
    #     assert missing_subscription_str == "", f"Missing subscription for {missing_subscription_str}"


    def test_fp_mitigation_proper_chain_id(self):
        agent.clear_state()
        agent.initialize(True)
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        # Read the content of package.json and store the original "name" field
        original_name = ""
        with open("package.json", "r") as package_file:
            package_data = json.load(package_file)
            original_name = package_data["name"]

        # Modify the "name" field to "beta" (as alt doesn't return labels for the test)
        package_data["name"] = "beta"
        with open("package.json", "w") as package_file:
            json.dump(package_data, package_file, indent=2)

        findings = agent.emit_new_fp_finding(w3)

        # Revert the "name" field back to its original value
        package_data["name"] = original_name
        with open("package.json", "w") as package_file:
            json.dump(package_data, package_file, indent=2)

        assert len(findings) > 0, "this should have triggered FP findings"
        finding = findings[0]
        assert finding.alert_id == "SCAM-DETECTOR-FALSE-POSITIVE", "should be FP mitigation finding"
        assert len(finding.labels) > 0, "labels should not be empty"
        label = finding.labels[0]
        assert label.entity == "0x8cc6b83d52b67f629fb3c5978cda3a6c2a456edc"
        assert label.metadata['address_type'] == "EOA"

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
        # tuple of entity, label, metadata (tuple of key value pairs)
        label_0 = list(sorted_fp_labels)[0]
        assert label_0[0] == EOA_ADDRESS_SMALL_TX.lower()
        assert label_0[1] == 'scammer'
        assert 'address_type=EOA' in label_0[2] 
        assert 'threat_category=address-poisoner' in label_0[2]
        label_1 = list(sorted_fp_labels)[1]
        assert label_1[0] == CONTRACT.lower()
        assert label_1[1] == 'scammer'
        assert 'address_type=contract' in label_1[2]
        assert 'threat_category=address-poisoner' in label_1[2]


    def test_obtain_all_fp_labels_scammer_association(self):
        # got address EOA_ADDRESS_LARGE_TX that was propagated from address EOA_ADDRESS_SMALL_TX
        agent.clear_state()
        agent.initialize()

        similar_contract_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])
        scammer_association_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])
        scammer_association_labels = pd.concat([scammer_association_labels, pd.DataFrame({'from_entity': [EOA_ADDRESS_LARGE_TX.lower()], 'to_entity': [EOA_ADDRESS_SMALL_TX.lower()]})], ignore_index=True)

        fp_labels = agent.obtain_all_fp_labels(w3, EOA_ADDRESS_LARGE_TX, block_chain_indexer, forta_explorer, similar_contract_labels, scammer_association_labels, 1)
        sorted_fp_labels = sorted(fp_labels, key=lambda x: x[0])
        sorted_fp_labels = list(sorted_fp_labels)
        assert len(sorted_fp_labels) == 4, "should have four FP labels; one for each EOA and contract"

        label_0 = list(sorted_fp_labels)[0]
        assert label_0[0] == EOA_ADDRESS_SMALL_TX.lower()
        assert label_0[1] == 'scammer'
        assert 'address_type=EOA' in label_0[2] 
        assert 'threat_category=address-poisoner' in label_0[2]
        label_3 = list(sorted_fp_labels)[3]
        assert label_3[0] == EOA_ADDRESS_LARGE_TX.lower()
        assert label_3[1] == 'scammer'
        assert 'address_type=EOA' in label_3[2]
        assert 'threat_category=address-poisoner' in label_3[2]
        
       
    def test_obtain_all_fp_labels_similar_contract(self):
        # got address A that deployed contract B; contract B propagated to contract D
        agent.clear_state()
        agent.initialize()

        similar_contract_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])
        new_labels = pd.DataFrame({'from_entity': [CONTRACT.lower()], 'from_entity_deployer': [EOA_ADDRESS_LARGE_TX.lower()], 'to_entity_deployer': [EOA_ADDRESS_SMALL_TX.lower()], 'to_entity': [CONTRACT2.lower()]})
        similar_contract_labels = pd.concat([similar_contract_labels, new_labels], ignore_index=True)
        scammer_association_labels = pd.DataFrame(columns=['from_entity', 'to_entity'])
        
        fp_labels = agent.obtain_all_fp_labels(w3, EOA_ADDRESS_LARGE_TX, block_chain_indexer, forta_explorer, similar_contract_labels, scammer_association_labels, 1)
        sorted_fp_labels = sorted(fp_labels, key=lambda x: x[0])
        sorted_fp_labels = list(sorted_fp_labels)
        assert len(sorted_fp_labels) == 4, "should have four FP labels; one for each EOA and contract"

    # 11/22/2023 - removed because we have not been able to ship this for some time now
    # def test_detect_ice_phishing_ml(self):
    #     agent.initialize()
    #     agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

    #     bot_id = "0x4aa29f0e18bd56bf85dd96f568a9affb5a367cec4df4b67f5b4ed303ff15271e"
    #     alert_id = "EOA-PHISHING-SCAMMER"
    #     description = "0xc6f5341d0cfea47660985b1245387ebc0dbb6a12 has been identified as a phishing scammer"
    #     metadata = {
    #         "scammer": "0xc6f5341d0cfea47660985b1245387ebc0dbb6a12",
    #         "feature_generation_time_sec": 55.393977834,
    #         "prediction_time_sec": 3.258650750000001,
    #         "feature_1_from_address_count_unique_ratio": 0.8977777777777778,
    #         "feature_2_from_address_nunique": 202,
    #         "feature_3_in_block_number_std": 103944.45395073255,
    #         "feature_4_in_ratio": 0.0000027220471162690886,
    #         "feature_5_ratio_from_address_nunique": 0.6824324324324325,
    #         "feature_6_total_time": 9495012,
    #         "feature_7_from_in_min_std": 0,
    #         "feature_8_from_in_block_timespan_median": 477557,
    #         "feature_9_from_out_min_std": 0,
    #         "feature_10_from_out_block_std_median": 166256.50317778645,
    #         "feature_11_to_in_sum_min": 48516.30387100715,
    #         "feature_12_to_in_sum_median": 196337.4491312858,
    #         "feature_13_to_in_sum_median_ratio": 5190.0165806816785,
    #         "feature_14_to_in_min_min": 1e-18,
    #         "feature_15_to_in_block_std_median": 236914.9074575176,
    #         "feature_16_to_out_min_std": 0,
    #         "anomaly_score": 1,
    #         "model_version": "1678286940",
    #         "model_threshold": 0.5,
    #         "model_score": 0.659,
    #     }
    #     label = {
    #         "entityType": "Address",
    #         "entity": "0xc6f5341d0cfea47660985b1245387ebc0dbb6a12",
    #         "label": "scammer-eoa",
    #         "confidence": 0.659,
    #         "remove": False,
    #         "metadata": {}
    #         }
    #     labels = [ label ]
    #     alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata, labels)

    #     findings = TestScamDetector.filter_findings(agent.detect_scam(w3, alert_event, clear_state_flag=True),"passthrough")

    #     assert len(findings) == 1, "this should have triggered a finding for delpoyer EOA"
    #     finding = findings[0]
    #     assert finding.alert_id == "SCAM-DETECTOR-UNKNOWN", "should be unknown finding"
    #     assert finding.metadata is not None, "metadata should not be empty"
    #     assert len(finding.labels) > 0, "labels should not be empty"
    #     assert finding.labels[0].entity == '0xc6f5341d0cfea47660985b1245387ebc0dbb6a12'
    #     assert finding.labels[0].label == 'scammer'
    #     assert finding.labels[0].confidence == 0.659


    def test_emit_new_manual_finding(self):
        agent.clear_state()
        agent.initialize(True)
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        # Read the content of package.json and store the original "name" field
        original_name = ""
        with open("package.json", "r") as package_file:
            package_data = json.load(package_file)
            original_name = package_data["name"]

        # Modify the "name" field to "beta" (as alt doesn't return labels for the test)
        package_data["name"] = "beta"
        with open("package.json", "w") as package_file:
            json.dump(package_data, package_file, indent=2)

        findings = agent.emit_manual_finding(w3, True)

        # Revert the "name" field back to its original value
        package_data["name"] = original_name
        with open("package.json", "w") as package_file:
            json.dump(package_data, package_file, indent=2)

        assert len(findings) == 4, "this should have triggered manual address findings"
        
        for finding in findings[:4]:
            address_lower = "0x5ae30eb89d761675b910e5f7acc9c5da0c85baaa".lower()
            if address_lower in finding.description.lower():
                assert finding.alert_id == "SCAM-DETECTOR-MANUAL-ICE-PHISHING", "should be SCAM-DETECTOR-MANUAL-ICE-PHISHING"
                assert finding.description == f"{address_lower} likely involved in an attack (SCAM-DETECTOR-MANUAL-ICE-PHISHING, manual)", "wrong description"
                assert finding.metadata["reported_by"] == "Blocksec "
                assert finding.metadata["attribution"] == "Inferno Drainer"
                assert finding.labels[0].entity == address_lower, "entity should be attacker address"
                assert finding.labels[0].metadata["attribution"] == "Inferno Drainer", "should be drainer"

        # Metamask phishing list findings
        for finding in findings[4:]:
            assert finding.alert_id == "SCAM-DETECTOR-MANUAL-METAMASK-PHISHING", "should be SCAM-DETECTOR-MANUAL-METAMASK-PHISHING"
            assert finding.description == f"{finding.labels[0].entity} likely involved in an attack (SCAM-DETECTOR-MANUAL-METAMASK-PHISHING, manual)", "wrong description"
            assert finding.metadata["reported_by"] == "Metamask "

    def test_scammer_contract_deployment_manual(self):
        Utils.TEST_STATE = True
        agent.clear_state()
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        # should result in 0xd89a4f1146ea3ddc8f21f97b562d97858d89d307, which matches the signature in the manual list
        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': '0x59d3BeE9C38C0b43cAEf8a83eC31e13d550EEa22',
                'nonce': 0,
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_scammer_contract_creation(w3, tx_event)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == f"SCAM-DETECTOR-MANUAL-ICE-PHISHING"
        found_contract = False
        for label in findings[0].labels:
            if label.label == 'scammer' and label.entity.lower() == '0xd89a4f1146ea3ddc8f21f97b562d97858d89d307':
                found_contract = True
                assert label.metadata['attribution'] == 'Inferno Drainer'
        assert found_contract


    def test_scammer_contract_deployment_dynamical(self):
        Utils.TEST_STATE = True
        agent.clear_state()
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': "0x00003ffA7857408ab714c28B1451914330240000", 
                'to': SCAM_CONTRACT_DEPLOYER,
                'nonce': 10,
            },
            'block': {
                'number': 18783860
            },
            'traces': [
                {'type': 'create',
                 'action': {
                     'from': SCAM_CONTRACT_DEPLOYER,
                     'value': 1,
                 },
                 'result': {
                     'address': "0x1bdd75c80ac5191245c656ed0f61ca73cb7018ac"
                 }
                }
            ],
            'receipt': {
                'logs': []}
        })

        findings = agent.detect_scammer_contract_creation(w3, tx_event)

        assert len(findings) == 1, "this should have triggered a finding"
        assert findings[0].alert_id == "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT"
        assert findings[0].metadata['scammer_contract_address'] == "0x1bdd75c80ac5191245c656ed0f61ca73cb7018ac"
        assert '0x9af49eb880e0ef621fd45c6cb8c4738f6f59dafa' in findings[0].metadata['future_contract_addresses']
        
    def test_fp_mitigation(self):
        # Requires bot version to be 'beta' to pass
        agent.clear_state()
        agent.initialize()
        agent.item_id_prefix = "test_" + str(random.randint(0, 1000000))

        findings = []

        bot_id = "0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127"
        alert_id = "IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR"
        description = "0xF45347C7E0F840F020F06a09665a0bcC4E092A38 deployed an impersonating token contract at 0xb4d91be6d0894de00a3e57c24f7abb0233814c86. It impersonates token USDC (USDC) at 0x115110423f4ad68a3092b298df7dc2549781108e"
        metadata = {"anomalyScore":"0.09375","newTokenContract":"0xb4d91be6d0894de00a3e57c24f7abb0233814c86","newTokenDeployer":"0xF45347C7E0F840F020F06a09665a0bcC4E092A38","newTokenName":"Cross Chain Token","newTokenSymbol":"USDC","oldTokenContract":"0x115110423f4ad68a3092b298df7dc2549781108e","oldTokenDeployer":"0x80ec4276d31b1573d53f5db75841762607bc2166","oldTokenName":"Cross Chain Token","oldTokenSymbol":"USDC"}
        alert_event = TestScamDetector.generate_alert(bot_id, alert_id, description, metadata)

        findings.extend(agent.handle_alert(alert_event))
       
        if Utils.is_beta():
            assert len(findings) == 1, "length should have been 1, alert for FP mitigation should have been triggered"
            finding = findings[0]
            assert finding.alert_id == "SCAM-DETECTOR-FP-MITIGATION", "should be fp mitigation finding"
            assert finding.metadata['etherscan_labels'] == "Proposer Fee Recipient"
            assert finding.metadata['etherscan_nametag'] == "Fee Recipient: 0xF4...A38"
            assert len(finding.labels) > 0, "labels should not be empty"
            assert finding.labels[0].label == 'benign', "should be a benign label"
        else:
            assert len(findings) == 0, "length should have been 0, inline FP mitigation should be triggered only in beta versions"
            
        