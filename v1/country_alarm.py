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
        configured_onts = response.json()

        # find and return all olt-channel-eltex combinations for usernum
        olt_channel_eltex = [(ont["LTP"][-1], ont["CHANNEL"], ont["ELTX"]) for ont in configured_onts if ont["USERNUM"] == str(usernum)]
        return olt_channel_eltex
    