#!/usr/bin/python3
import os
import requests


##### MANAGER TO GET DATA FROM COUNTRY ALARM #####

class CountryAlarmManager:
    # url for all configured onts, no matter online or not
    __url = os.getenv("URL_CONFIGURED_ONTS")

    # get olt ips and eltex serials by usernum
    @staticmethod
    def get_user_data_from_alarm(usernum: int):
        # load json from url
        response = requests.get(CountryAlarmManager.__url)
        payload = response.json()

        # split and collect data as dictionaries
        columns = payload["columns"]
        data = payload["data"]
        configured_onts = [dict(zip(columns, line)) for line in data]

        # find and return all pairs of olt and eltex for usernum
        return [(ont["LTP"], ont["ELTX"]) for ont in configured_onts if ont["USERNUM"] == str(usernum)]
    