from datetime import datetime


class LuabaseMock:
    def get_denominator(self, ad_scorer: str, start_date: datetime, end_date: datetime):
        if ad_scorer == 'contract-creation':
            return 1000
        elif ad_scorer == 'contract-interactions':
            return 1000
        elif ad_scorer == 'tx-count':
            return 100000
        elif ad_scorer == 'transfer-in':
            return 10000
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
       
