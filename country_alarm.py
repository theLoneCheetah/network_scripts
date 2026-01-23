#!/usr/bin/python3
import os
import requests
# user's modules
from const import Country


##### MANAGER TO GET DATA FROM COUNTRY ALARM #####

class CountryAlarmManager:
    # get olt ips and eltex serials by usernum
    @staticmethod
    def get_user_data_from_alarm(usernum: int) -> list[tuple[str]]:
        # load json from url
        response = requests.get(Country.ALARM_URL)
        payload = response.json()

        # split and collect data as dictionaries
        columns = payload["columns"]
        data = payload["data"]
        configured_onts = [dict(zip(columns, line)) for line in data]

        # find and return all pairs of olt and eltex for usernum
        return [(ont["LTP"], ont["ELTX"]) for ont in configured_onts if ont["USERNUM"] == str(usernum)]
    