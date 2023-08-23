from datetime import datetime
import json
from forta_agent import get_json_rpc_url, FindingSeverity
from web3 import Web3
from utils import Utils
from web3_mock import CONTRACT, EOA_ADDRESS_SMALL_TX, Web3Mock, EOA_ADDRESS_LARGE_TX

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

class TestUtils:
    def test_is_contract_eoa(self):
        assert not Utils.is_contract(w3, EOA_ADDRESS_SMALL_TX), "EOA shouldn't be identified as a contract"

    def test_is_contract_contract(self):
        assert Utils.is_contract(w3, CONTRACT), "Contract should be identified as a contract"

    def test_is_contract_contract_eoa(self):
        assert not Utils.is_contract(w3, f"{CONTRACT},{EOA_ADDRESS_SMALL_TX}"), "EOA & Contract shouldnt be identified as a contract"

    def test_is_contract_contracts(self):
        assert Utils.is_contract(w3, f"{CONTRACT},{CONTRACT}"), "Contracts should be identified as a contract"

    def test_is_contract_null(self):
        assert not Utils.is_contract(w3, '0x0000000000a00000000000000000000000000000'), "EOA shouldn't be identified as a contract"

    def test_is_address_valid(self):
        assert Utils.is_address(w3, '0x7328BBc3EaCfBe152f569f2C09f96f915F2C8D73'), "this should be a valid address"

    def test_is_address_aaa(self):
        assert not Utils.is_address(w3, '0x7328BBaaaaaaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_is_addresses_aaa(self):
        assert not Utils.is_address(w3, f'0x7328BBaaaaaaaaa52f569f2C09f96f915F2C8D73,{EOA_ADDRESS_SMALL_TX}'), "this shouldnt be a valid address"

    def test_is_address_aAa(self):
        assert not Utils.is_address(w3, '0x7328BBaaaaAaaaa52f569f2C09f96f915F2C8D73'), "this shouldnt be a valid address"

    def test_etherscan_label(self):
        label = Utils.get_etherscan_label("0xffc0022959f58aa166ce58e6a38f711c95062b99")
        assert 'uniswap' in label, "this should be a uniswap address"

    def test_max_tx_count(self):
        assert Utils.get_max_tx_count(w3, EOA_ADDRESS_SMALL_TX) == 1999, "this should be 1999"

    def test_is_in_fp_mitigation_list(self):
        Utils.TEST_STATE = True
        Utils.update_fp_list(1)
        assert Utils.is_in_fp_mitigation_list("0x8cc6b83d52b67f629fb3c5978cda3a6c2a456edc"), "it should be in list for chain 1"

    def test_fp_etherscan_label(self):
        assert Utils.is_fp(w3, "0xffc0022959f58aa166ce58e6a38f711c95062b99", 1), "this should be a false positive"

    def test_fp_max_tx_count(self):
        assert Utils.is_fp(w3, EOA_ADDRESS_LARGE_TX, 1), "this should be a false positive"

    def test_fp_mitigation_addresses(self):
        assert Utils.is_fp(w3, "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0", 1), "this should be a false positive"

    def test_get_total_shards(self):
        assert Utils.get_total_shards(w3) == 8, "this should be 8"

    def test_get_shard(self):
        
        assert Utils.get_shard(1, datetime(2023, 1, 1).timestamp()) == 0, "this should be 0"

    def test_get_bot_version(self):
        assert "." in Utils.get_bot_version()

    def test_is_beta(self):
        assert Utils.is_beta() is not None

    def test_is_fp_investigation1(self):
        assert not Utils.is_fp(real_w3, "0x61fF13F129a96d2d229D37A0531979852945433a".lower(), 1), "this should not be a false positive"

    def test_calc_contract_address(self):
        contract_address = Utils.calc_contract_address(w3, EOA_ADDRESS_SMALL_TX, 9)
        assert contract_address == "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7", "should be the same contract address"

    def test_decrypt_alert(self):
        private_key = ""
        with open("secrets.json") as f:
            secrets_json = json.load(f)
            if "BLOCKSEC" in secrets_json['decryptionKeys']:
                private_key = secrets_json['decryptionKeys']["BLOCKSEC"]
             
        encrypted_finding_base64 = "-----BEGIN PGP MESSAGE-----\n\nwV4Dsrw6yC2ErRsSAQdAH4G1wHZ51oEkY1qabIqDgy2fCO4tyPQQ8lTkUx2U\n8yUw7PknK6WzKO08VAzP5ME6s9uDOyhDg7A7rn2h4Sx1yW3sv264/r2yiKAq\nWJK+fIdd0sD5AaVkIyGWLhBnLBe+UYVhcYPh+6ynB1Vm2rh4l/qndcgIex6d\nTb/uriimCuMSZvUM4EfPzEZ1R/v0I//ryOJESS8PespcuczAQTYfwNUFXLKb\nGIhvjLwtwAeqOMnnukWFK3VGx8FodPEGjpVHGKP6tetY40np4saorsflamhu\nGI+mPOxm/5jc+r1D0zVVcjPNQ7n2rgr/PKhdiNwlkbK123HAvSIfDMxMeBs0\npD8T9LABU3P4wR2MGw6t0935o1tKUf0MiymSpsxqjrhrYsGBcIaMtomLO9eM\nFLs1/cLG8g5DQlcz3zkTFtcPHSt7mh4rio9en8a4ZzXoUiRhbD6DSFXsnuEt\n7VZ0UnTVES6J+YfUFiMTiFhXwZ07xxMWn8/LNfJUa2ADSIBpFOM6uVslhwxo\nuU0l29Sm09EWa0MXTf3Qo73VbzVb1NpwwwSeIUN/e3QbtE/udgeWhrwQXk91\nw25m1GSQCnO2oWenRSudvbbbir9Ew3kCi9aosOPM9iMCNk2HUGtS7FpRAz2A\nQwoNV2WOIR01VVDjdnguF/JKaeMrBqTOEqlqIqH60haJ1ct9wfjidoqBaA0V\n=YuOS\n-----END PGP MESSAGE-----\n"
        decrypted_finding = Utils.decrypt_alert(encrypted_finding_base64, private_key)
        assert decrypted_finding.description == "Ice phishing report."
        assert decrypted_finding.severity == FindingSeverity.Critical

    def test_debug_error(self):
        finding = Utils.alert_error("description", "source", "stacktrace")
        assert finding.description == "description"
        assert finding.alert_id == "DEBUG-ERROR"
        assert finding.severity == FindingSeverity.Info
        assert finding.name == "Scam detector encountered a recoverable error."
        assert finding.metadata['error_source'] == "source"
        assert finding.metadata['error_stacktrace'] == "stacktrace"
