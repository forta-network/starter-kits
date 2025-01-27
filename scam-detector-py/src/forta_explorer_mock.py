
from datetime import datetime
import pandas as pd

from web3_mock import EOA_ADDRESS_SMALL_TX, CONTRACT, EOA_ADDRESS_LARGE_TX, CONTRACT2

class FortaExplorerMock:
    @staticmethod
    def get_labels(source_id: str, start_date: datetime, end_date: datetime, entity: str = "", label_query: str = "") -> pd.DataFrame:

        labels_df = pd.DataFrame(columns=['createdAt', 'id', 'label', 'source', 'alertId', 'alertHash', 'chainId', 'labelstr', 'entity', 'entityType', 'remove', 'confidence', 'metadata', 'uniqueKey', 'botVersion', ])

        if entity == '0xe22536ac6f6a20dbb283e7f61a880993eab63313':
            temp = pd.DataFrame(columns = ['createdAt', 'id', 'label', 'source', 'alertId', 'alertHash', 'chainId', 'labelstr', 'entity', 'entityType', 'remove', 'confidence', 'metadata', 'botVersion', ], data = [[
                '2023-03-05 16:01:00',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbfffff',
                'label_obj',
                'source_obj',
                'SCAM-DETECTOR-ADDRESS-POISONER',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbaaaaa',
                1,
                'scammer',
                '0xe22536ac6f6a20dbb283e7f61a880993eab63313',
                'addresss',
                False,
                0.9,
                {"address_type":"contract","logic":"passthrough","threat_category":"address-poisoner"},
                '0.2.0'
            ]])
            labels_df = pd.concat([labels_df, temp])

        if entity == EOA_ADDRESS_SMALL_TX.lower():
            temp = pd.DataFrame(columns = ['createdAt', 'id', 'label', 'source', 'alertId', 'alertHash', 'chainId', 'labelstr', 'entity', 'entityType', 'remove', 'confidence', 'metadata', 'botVersion', ], data = [[
                '2023-03-05 16:01:00',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbfffff',
                'label_obj',
                'source_obj',
                'SCAM-DETECTOR-ADDRESS-POISONER',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbaaaaa',
                1,
                'scammer',
                EOA_ADDRESS_SMALL_TX,
                'addresss',
                False,
                0.9,
                {"address_type":"EOA","logic":"passthrough","threat_category":"address-poisoner"},
                '0.2.0'
            ]])
            labels_df = pd.concat([labels_df, temp])

        if entity == EOA_ADDRESS_LARGE_TX.lower():
            temp = pd.DataFrame(columns = ['createdAt', 'id', 'label', 'source', 'alertId', 'alertHash', 'chainId', 'labelstr', 'entity', 'entityType', 'remove', 'confidence', 'metadata', 'uniqueKey' 'botVersion', ], data = [[
                '2023-03-05 16:01:00',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbfffff',
                'label_obj',
                'source_obj',
                'SCAM-DETECTOR-ADDRESS-POISONER',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbaaaaa',
                1,
                'scammer',
                EOA_ADDRESS_LARGE_TX,
                'addresss',
                False,
                0.9,
                {"address_type":"EOA","logic":"passthrough","threat_category":"address-poisoner"},
                '0xabcd'
                '0.2.0'
            ]])
            labels_df = pd.concat([labels_df, temp])

        if entity == CONTRACT.lower() or entity == CONTRACT2.lower():
            temp = pd.DataFrame(columns = ['createdAt', 'id', 'label', 'source', 'alertId', 'alertHash', 'chainId', 'labelstr', 'entity', 'entityType', 'remove', 'confidence', 'metadata', 'botVersion', ], data = [[
                '2023-03-05 16:01:00',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbfffff',
                'label_obj',
                'source_obj',
                'SCAM-DETECTOR-ADDRESS-POISONER',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbaaaaa',
                1,
                'scammer',
                CONTRACT,
                'addresss',
                False,
                0.9,
                {"address_type":"contract","logic":"passhthrough","threat_category":"address-poisoner"},
                '0.2.0'
            ]])
            labels_df = pd.concat([labels_df, temp])


        if entity == '' and label_query == 'scammer-association':
            temp = pd.DataFrame(columns = ['createdAt', 'id', 'label', 'source', 'alertId', 'alertHash', 'chainId', 'labelstr', 'entity', 'entityType', 'remove', 'confidence', 'metadata', 'botVersion', ], data = [[
                '2023-03-05 16:01:00',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbaaaaa',
                'label_obj',
                'source_obj',
                'SCAM-DETECTOR-SCAMMER-ASSOCIATION',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbbbbbb',
                1,
                'scammer',
                '0x3805ad836968b7d844eac2fe0eb312ccc37e463a',
                'addresss',
                False,
                0.9,
                {"threat_category":"scammer-association","address_type":"EOA","logic":"propagation","base_bot_alert_ids":"ADDRESS-POISONING-FAKE-TOKEN","base_bot_alert_hashes":"0x003e7643042d22f54b817ed14003ad6acbee18f40a818b4e5edadd75d9e9b617","threat_description_url":"https://forta.org/attacks#address-poisoning","bot_version":"0.2.2","associated_scammer":"0x3805ad836968b7d844eac2fe0eb312ccc37e4630"},
                '0.2.0'
            ]])
            labels_df = pd.concat([labels_df, temp])
        
        labels_df['createdAt'] = pd.to_datetime(labels_df['createdAt'])
        return labels_df
