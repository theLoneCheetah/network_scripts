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

        # print ltp-channel
        print(" ".join(f"{ont["LTP"][-1:]}-{ont["CHANNEL"]}" for ont in configured_onts if ont["USERNUM"] == str(usernum)))

        # find and return all pairs of olt and eltex for usernum
        return [(Country.BASE_SUBNET + ont["LTP"][-1], ont["ELTX"]) for ont in configured_onts if ont["USERNUM"] == str(usernum)]
    