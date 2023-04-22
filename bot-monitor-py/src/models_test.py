from models import AlertRateModel
import pandas as pd
from prophet import Prophet
from datetime import datetime, timezone

class TestUtils:
    def test_alert_rate_model_in_range(self):
        # Initialize AlertRateModel
        alert_rate_model = AlertRateModel()
        start_time = datetime(2020, 12, 31, 23, 0, tzinfo=timezone.utc)
        # Create sample timestamps
        timestamp_1 = datetime(2021, 1, 1, 0, 0, tzinfo=timezone.utc)
        timestamp_2 = datetime(2021, 1, 1, 1, 0, tzinfo=timezone.utc)
        timestamp_3 = datetime(2021, 1, 1, 2, 0, tzinfo=timezone.utc)
        timestamp_4 = datetime(2021, 1, 1, 3, 0, tzinfo=timezone.utc)

        # Update the model with the sample timestamps
        alert_rate_model.update(timestamp_1)
        alert_rate_model.update(timestamp_2)
        alert_rate_model.update(timestamp_2)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_4)
        alert_rate_model.update(timestamp_4)
        alert_rate_model.update(timestamp_4)

        last_hour = timestamp_4.replace(minute=0, second=0, microsecond=0)
        lower_bound, upper_bound, last_hour_value = alert_rate_model.get_normal_range(last_hour, start_time)
        assert last_hour_value < upper_bound and last_hour_value > lower_bound

    def test_alert_rate_model_missing_value(self):
        # Initialize AlertRateModel
        alert_rate_model = AlertRateModel()
        start_time = datetime(2020, 12, 31, 23, 0, tzinfo=timezone.utc)
        alert_rate_model.update(start_time)

        # Create sample timestamps
        timestamp_1 = datetime(2021, 1, 1, 0, 0, tzinfo=timezone.utc)
        timestamp_3 = datetime(2021, 1, 1, 2, 0, tzinfo=timezone.utc)
        timestamp_4 = datetime(2021, 1, 1, 3, 0, tzinfo=timezone.utc)

        # Update the model with the sample timestamps
        alert_rate_model.update(timestamp_1)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_4)
        alert_rate_model.update(timestamp_4)

        last_hour = timestamp_4.replace(minute=0, second=0, microsecond=0)
        lower_bound, upper_bound, last_hour_value = alert_rate_model.get_normal_range(last_hour, start_time)
        assert last_hour_value < upper_bound and last_hour_value > lower_bound

    def test_get_time_series_date(self):
        # Initialize AlertRateModel
        alert_rate_model = AlertRateModel()
        start_time = datetime(2020, 12, 31, 23, 0, tzinfo=timezone.utc)
        alert_rate_model.update(start_time)

        # Create sample timestamps
        timestamp_1 = datetime(2021, 1, 1, 0, 0, tzinfo=timezone.utc)
        timestamp_3 = datetime(2021, 1, 1, 2, 0, tzinfo=timezone.utc)
        timestamp_4 = datetime(2021, 1, 1, 3, 0, tzinfo=timezone.utc)

        # Update the model with the sample timestamps
        alert_rate_model.update(timestamp_1)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_4)
        alert_rate_model.update(timestamp_4)

        time_series = alert_rate_model.get_time_series_data(timestamp_4, start_time)
        assert time_series == "1.0,0.0,2.0"

    def test_alert_rate_model_in_range_repeat_call(self):
        # Initialize AlertRateModel
        alert_rate_model = AlertRateModel()
        start_time = datetime(2020, 12, 31, 23, 0, tzinfo=timezone.utc)
        # Create sample timestamps
        timestamp_1 = datetime(2021, 1, 1, 0, 0, tzinfo=timezone.utc)
        timestamp_2 = datetime(2021, 1, 1, 1, 0, tzinfo=timezone.utc)
        timestamp_3 = datetime(2021, 1, 1, 2, 0, tzinfo=timezone.utc)
        timestamp_4 = datetime(2021, 1, 1, 3, 0, tzinfo=timezone.utc)

        # Update the model with the sample timestamps
        alert_rate_model.update(timestamp_1)
        alert_rate_model.update(timestamp_2)
        alert_rate_model.update(timestamp_2)
        alert_rate_model.update(timestamp_2)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_4)
        alert_rate_model.update(timestamp_4)
        

        last_hour = timestamp_4.replace(minute=0, second=0, microsecond=0)
        lower_bound, upper_bound, last_hour_value = alert_rate_model.get_normal_range(last_hour, start_time)
        
        timestamp_5 = datetime(2021, 1, 1, 4, 0, tzinfo=timezone.utc)
        alert_rate_model.update(timestamp_5)
        alert_rate_model.update(timestamp_5)
        alert_rate_model.update(timestamp_5)
        last_hour = timestamp_5.replace(minute=0, second=0, microsecond=0)
        lower_bound, upper_bound, last_hour_value = alert_rate_model.get_normal_range(last_hour, start_time)
        assert last_hour_value < upper_bound and last_hour_value > lower_bound