
from datetime import datetime
import pandas as pd

from web3_mock import EOA_ADDRESS_SMALL_TX, CONTRACT

class FortaExplorerMock:
    @staticmethod
    def get_labels(entity: str, source_id: str, start_date: datetime, end_date: datetime) -> pd.DataFrame:

        labels_df = pd.DataFrame(columns=['createdAt', 'id', 'label', 'source', 'alertId', 'alertHash', 'chainId', 'labelstr', 'entity', 'entityType', 'remove', 'confidence', 'metadata', 'botVersion', ])

        if entity == '0xe22536ac6f6a20dbb283e7f61a880993eab63313':
            temp = pd.DataFrame(columns = ['createdAt', 'id', 'label', 'source', 'alertId', 'alertHash', 'chainId', 'labelstr', 'entity', 'entityType', 'remove', 'confidence', 'metadata', 'botVersion', ], data = [[
                '2023-03-05 16:01:00',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbfffff',
                'label_obj',
                'source_obj',
                'SCAM-DETECTOR-ADDRESS-POISONER',
                '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacbaaaaa',
                1,
                'scammer-contract/address-poisoner/passhthrough',
                '0xe22536ac6f6a20dbb283e7f61a880993eab63313',
                'addresss',
                False,
                0.9,
                'metadata',
                '0.2.0'
            ]])
            labels_df = pd.concat([labels_df, temp])
        
        labels_df['createdAt'] = pd.to_datetime(labels_df['createdAt'])
        return labels_df
