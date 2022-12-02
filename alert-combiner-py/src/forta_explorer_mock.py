from datetime import datetime
import pandas as pd


class FortaExplorerMock:

    df = pd.DataFrame(columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash', 'transactionHash'])

    def empty_alerts(self) -> pd.DataFrame:
        df_forta = pd.DataFrame(columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash', 'bot_id', 'transactionHash'])
        return df_forta

    def alerts_by_bot(self, bot_id: str, alert_ids: set, chain_id: int, start_date: datetime, end_date: datetime, results_limit: int = 0) -> pd.DataFrame:
        self.df["bot_id"] = self.df["source"].apply(lambda x: x["bot"]["id"])
        self.df["transactionHash"] = self.df["source"].apply(lambda x: x["transactionHash"])
        return self.df[self.df["bot_id"] == bot_id]

    def set_df(self, df_forta: pd.DataFrame):
        self.df = df_forta
