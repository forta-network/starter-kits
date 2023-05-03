import logging
import forta_agent
from forta_agent import EntityType


class BaseBotParser:

    @staticmethod
    def get_sleep_minting_addresses(description: str) -> str:
        # An NFT Transfer was initiated by 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to transfer an NFT owned by 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. It had been previously minted by the 0x09b34e69363d37379e1c5e27fc793fdb5aca893d to 0xeb9fcf2fb7c0d95edc5beb9b142e8c024d885fb2. The NFT contract address is 0xd57474e76c9ebecc01b65a1494f0a1211df7bcd8
        loc = len("An NFT Transfer was initiated by ")
        return description[loc:loc+42]

    @staticmethod
    def get_hard_rug_pull_deployer(metadata: dict) -> set:
        
        addresses = set()
        if "attacker_deployer_address" in metadata:
            addresses.add(metadata["attacker_deployer_address"].lower())
        if "attackerDeployerAddress" in metadata:
            addresses.add(metadata["attackerDeployerAddress"].lower())
        logging.info(f"Found {len(addresses)} addresses in hard rug pull metadata")
        return addresses

    @staticmethod
    def get_soft_rug_pull_deployer(metadata: dict) -> set:
        addresses = set()
        if "deployer" in metadata:
            addresses.add(metadata["deployer"].lower().strip('"'))
        logging.info(f"Found {len(addresses)} addresses in soft rug pull metadata")
        return addresses

    @staticmethod
    def get_rake_token_deployer(metadata: dict) -> set:
        addresses = set()
        if "attackerRakeTokenDeployer" in metadata:
            addresses.add(metadata["attackerRakeTokenDeployer"].lower())
        if "attacker_rake_token_deployer" in metadata:
            addresses.add(metadata["attacker_rake_token_deployer"].lower())
        logging.info(f"Found {len(addresses)} addresses in rake token metadata")
        return addresses

    @staticmethod
    def get_wash_trading_addresses(metadata: dict) -> set:
        addresses = set()
        if "buyerWallet" in metadata:
            addresses.add(metadata["buyerWallet"].lower())
        if "sellerWallet" in metadata:
            addresses.add(metadata["sellerWallet"].lower())
        if "buyer_wallet" in metadata:
            addresses.add(metadata["buyer_wallet"].lower())
        if "seller_wallet" in metadata:
            addresses.add(metadata["seller_wallet"].lower())
        logging.info(f"Found {len(addresses)} addresses in wash trading metadata")
        return addresses


    @staticmethod
    def get_address_poisoning_addresses_poisoner(metadata: dict) -> set:
        print(f"address poisoning metadata: {metadata}")
        addresses = set()
        if "phishingEoa" in metadata:
            addresses.add(metadata["phishingEoa"].lower())
        if "phishingContract" in metadata:
            addresses.add(metadata["phishingContract"].lower())
        if "phishing_eoa" in metadata:
            addresses.add(metadata["phishing_eoa"].lower())
        if "phishing_contract" in metadata:
            addresses.add(metadata["phishing_contract"].lower())
        logging.info(f"Found {len(addresses)} addresses in address poisoner metadata")
        return addresses

    @staticmethod
    def get_address_poisoning_addresses_poisoning(metadata: dict) -> set:
        print(f"address poisoning metadata: {metadata}")
        addresses = set()
        if "attackerAddresses" in metadata:
            attacker_addresses = metadata["attackerAddresses"]
            for attacker_address in attacker_addresses.split(","):
                addresses.add(attacker_address.lower())
        if "attacker_addresses" in metadata:
            attacker_addresses = metadata["attacker_addresses"]
            for attacker_address in attacker_addresses.split(","):
                addresses.add(attacker_address.lower())
        logging.info(f"Found {len(addresses)} addresses in address poisoning metadata")
        return addresses


    @staticmethod
    def get_native_ice_phishing_address(metadata: dict) -> str:
        if "attacker" in metadata:
            return metadata["attacker"]
        return ""


    @staticmethod
    def get_seaport_order_attacker_address(metadata: dict) -> str:
        if "toAddr" in metadata:
            return metadata["toAddr"]
        if "to_addr" in metadata:
            return metadata["to_addr"]
        if "initiator" in metadata:
            return metadata["initiator"]
        return ""


    @staticmethod
    def get_scammer_addresses(alert_event: forta_agent.alert_event.AlertEvent) -> set:
        scammer_addresses = set()
        for label in alert_event.alert.labels:
            label_lower = label.label.lower()
            if ("scam" in label_lower or "attack" in label_lower) and label.entity_type == EntityType.Address:
                scammer_addresses.add(label.entity.lower())

        if alert_event.alert.metadata is not None:
            for key in ["attackerAddresses", "attacker_address"]:
                if key in alert_event.alert.metadata.keys():  # address poisoning bot
                    attacker_addresses = alert_event.alert.metadata[key]
                    for attacker_address in attacker_addresses.split(','):
                        scammer_addresses.add(attacker_address.lower())

        return scammer_addresses