# Copyright 2022 The Forta Foundation

from datetime import datetime


class LuabaseMock:
    def populate_denominator_cache(self, chain_id: int, ad_scorer: str, start_date: datetime, end_date: datetime):
        return

    def populate_alert_count_cache(self, chain_id: int, bot_id: str, alert_id: str, start_date: datetime, end_date: datetime):
        return

    def get_denominator(self, chain_id: int, ad_scorer: str, start_date: datetime, end_date: datetime):
        if ad_scorer == 'contract-creation':
            return 1000
        elif ad_scorer == 'contract-interactions':
            return 10000
        elif ad_scorer == 'tx-count':
            return 10000000
        elif ad_scorer == 'transfer-in':
            return 100000
        elif ad_scorer == 'transfer-out-large-amount':
            return 100
        elif ad_scorer == 'data-eoa-to':
            return 100
        elif ad_scorer == 'erc-approvalAll':
            return 1000
        elif ad_scorer == 'erc-approvals':
            return 1000
        elif ad_scorer == 'erc-transfers':
            return 1000
        else:
            raise ValueError(f"Invalid ad scorer: {ad_scorer}")

    def get_alert_count(self, chain_id: int, bot_id: str, alert_id: str, start_date: datetime, end_date: datetime):
        if bot_id == '0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400' and alert_id == 'FUNDING-TORNADO-CASH':
            return 100
        elif bot_id == '0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91' and alert_id == 'SUSPICIOUS-CONTRACT-CREATION':
            return 200
        elif bot_id == '0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5' and alert_id == 'FLASHBOTS-TRANSACTIONS':
            return 50
        elif bot_id == '0xaedda4252616d971d570464a3ae4a9f0a9d72a57d8581945fff648d03cd30a7d' and alert_id == 'FORTA-BLOCKLIST-ADDR-TX':
            return 1000
        else:
            raise ValueError(f"Invalid bot_id and alert_id : {bot_id}, {alert_id}")
