from datetime import datetime
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
        Utils.update_fp_list(1)
        assert Utils.is_in_fp_mitigation_list("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"), "it should be in list for chain 1"

    def test_fp_etherscan_label(self):
        assert Utils.is_fp(w3, "0xffc0022959f58aa166ce58e6a38f711c95062b99"), "this should be a false positive"

    def test_fp_max_tx_count(self):
        assert Utils.is_fp(w3, EOA_ADDRESS_LARGE_TX), "this should be a false positive"

    def test_fp_mitigation_addresses(self):
        assert Utils.is_fp(w3, "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"), "this should be a false positive"

    def test_get_total_shards(self):
        assert Utils.get_total_shards(w3) == 8, "this should be 8"

    def test_get_shard(self):
        
        assert Utils.get_shard(1, datetime(2023, 1, 1).timestamp()) == 0, "this should be 0"

    def test_get_bot_version(self):
        assert "." in Utils.get_bot_version()

    def test_is_beta(self):
        assert Utils.is_beta() is not None

    def test_is_fp_investigation1(self):
        assert not Utils.is_fp(real_w3, "0x61fF13F129a96d2d229D37A0531979852945433a".lower()), "this should not be a false positive"

    def test_calc_contract_address(self):
        contract_address = Utils.calc_contract_address(w3, EOA_ADDRESS_SMALL_TX, 9)
        assert contract_address == "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7", "should be the same contract address"

    def test_decrypt_alert(self):
        private_key = """-----BEGIN PGP PRIVATE KEY BLOCK-----

            lFgEZJIQ9hYJKwYBBAHaRw8BAQdAY6YD5hXuNB7oimaPkIELdzQk6VYmvLHxdqJO
            1UoQd2gAAP0dVkKilX6K3FRvJHYW2kXgtJ3dZsSc402A6o5mb8x75xJetB10ZXN0
            Ym90IDxjaHJpc3RpYW5AZm9ydGEub3JnPoiZBBMWCgBBFiEEjF1uj3b2d/+HmkTI
            qEvWFEVu298FAmSSEPYCGwMFCQPCZwAFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcC
            F4AACgkQqEvWFEVu2990yQD/UU67YegN3k20JjnqMpW0aNigcf5kTzIn9FcrU6MC
            iDoBAOElTXMmnt9oZs6dQpYLlSZzC/CI8H6zHSSs6Nlcc8QCnF0EZJIQ9hIKKwYB
            BAGXVQEFAQEHQCTiGxlIkqUmKp7jmbF9UFucNYTq+iBfpnYWwWYTBssJAwEIBwAA
            /1dqhB72vIyb8i1Fcfx4jCMRIs+CwJ2AlGFhmxQa84HQEPeIfgQYFgoAJhYhBIxd
            bo929nf/h5pEyKhL1hRFbtvfBQJkkhD2AhsMBQkDwmcAAAoJEKhL1hRFbtvfG5QB
            APGHT9livgHLS7Oxnh6Au7z2JY7xn+c6f4stenK61YWzAQCinZ7aWt++joCS5N0A
            wZDC9xAZrMkN9JqSM6HfyEhSBg==
            =ao/0
            -----END PGP PRIVATE KEY BLOCK-----
            """
        
        encrypted_finding_base64 = "LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tCgpoRjREWWlMaW5IS2xIQ0FTQVFkQVZHWDRBWCtVMTR1NkVDK3VRczYxbjA5QmRDUjd6WiszekNpVy9EVTNwV0l3CnJrMTg2VGFkTzFLTWdTUUx1YWRIcEtHd201QUlJZFRvdHN2K0NYTGdHd0pRK3lpQUZvckxLd1dyR3lvNUtDdngKMHNBREFUS2IwYkhxWVVYMUE4U0NLdVE2ZjY0Mmd2dVltanhCUXFRd1ZWenFscEY1VHEyT3Rmdi9JMDhxUElObAprN2Z3RjRKcUVjaFlncVYrRkhHb2h6NzZRYXYzNVpOLzhvbXpZbjN5WTF2RUdtR3pMRnQ5TGxUTFpIRys5NVc0ClNXR1pmZklXUDFJczFSTXBCNXBIOWxVai9hTGRUQzY5dHNnTHp5UUtuWDU3WXBnWjUyeHhFQ2hWRGthbWZzVU0KdXMwN1ZmNVpuQWdoQ3JyZVRjalYvVFU3WUZYN2NTR3pZQkRzZFFEV2V1ZE1FVzZ4T2xYQkJWV2JFSEplNGlXcwppbVRxWmZITwo9SHBMMwotLS0tLUVORCBQR1AgTUVTU0FHRS0tLS0tCg=="
        decrypted_finding = Utils.decrypt_alert(encrypted_finding_base64, private_key)
        assert decrypted_finding.description == "Random value: 2.1856566476463613e-05"
        assert decrypted_finding.severity == FindingSeverity.Low
