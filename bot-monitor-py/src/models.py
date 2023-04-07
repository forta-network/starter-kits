import pandas as pd
from prophet import Prophet
from datetime import datetime

class AlertRateModel:
    def __init__(self):
        self.model = Prophet(interval_width=0.90)
        self.data = pd.DataFrame(columns=['ds', 'y'])
        
    def update(self, timestamp: datetime):
        # Truncate the timestamp to an hourly level
        timestamp = timestamp.replace(minute=0, second=0, microsecond=0)

        # Check if the timestamp already exists in the data
        row = self.data.loc[self.data['ds'] == timestamp]

        if row.empty:
            # Add a new row for the timestamp with an initial count of 1
            self.data = self.data.append({'ds': timestamp, 'y': 1}, ignore_index=True)
        else:
            # Increment the existing row count by 1
            self.data.loc[self.data['ds'] == timestamp, 'y'] += 1

        first_hour = self.data['ds'].min()
        last_hour = self.data['ds'].max()
        self.data.set_index('ds', inplace=True)
        complete_date_range = pd.date_range(first_hour, last_hour, freq='H')

        self.data = self.data.reindex(complete_date_range).fillna(0)
        self.data.reset_index(inplace=True)
        self.data.columns = ['ds', 'y']

    # fit the model based on data up to the last hour and assess whether the last hour is within the expected range of the model   
    def is_outside_normal_range(self, last_hour: datetime):
        train_data = self.data[self.data['ds'] < last_hour]
        self.model.fit(train_data)

        # Create a dataframe with the last hour
        future = pd.DataFrame({'ds': [last_hour]})

        # Predict for the last hour
        forecast = self.model.predict(future)
        
        # Check if the last hour is within the expected range of the model
        lower_bound = forecast['yhat_lower'].iloc[0]
        upper_bound = forecast['yhat_upper'].iloc[0]
        last_hour_value = self.data.loc[self.data['ds'] == last_hour, 'y'].iloc[0]

        return not (lower_bound <= last_hour_value <= upper_bound)
