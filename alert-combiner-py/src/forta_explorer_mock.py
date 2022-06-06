from datetime import datetime
import pandas as pd


class FortaExplorerMock:

    df = pd.DataFrame(columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

    def empty_alerts(self) -> pd.DataFrame:
        df_forta = pd.DataFrame(columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])
        return df_forta

    def alerts_by_bot(self, bot_id: str, start_date: datetime, end_date: datetime, results_limit: int = 0) -> pd.DataFrame:
        return self.df

    def set_df(self, df_forta: pd.DataFrame):
        self.df = df_forta
