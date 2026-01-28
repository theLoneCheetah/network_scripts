#!/usr/bin/python3
import re
import traceback
import signal
import sys
import os
from abc import ABC
from typing import Any, override
from ipaddress import IPv4Address, IPv4Network, AddressValueError
# user's modules
from diag_handler import DiagHandler
from database_manager import DatabaseManager
from base_olt import BaseOLT
from L2_switch import L2Switch
from L3_switch import L3Switch
from const import Database, Country
from country_alarm import CountryAlarmManager
from my_exception import ExceptionType, MyException


##### MANAGER FOR COUNTRY OLT VERSION 2 #####

class OLTVersion3(BaseOLT):
    def __init__(self, ipaddress: str, eltex_serial: str, print_output: bool) -> None:
        super().__init__(ipaddress, eltex_serial, print_output)
        
        # flag for terminal model type
        self.__ntu1 = False
    
    # base prompt symbol
    @override
    @property
    def _base_prompt(self):
        return "#"
    
    # command and regex for get_state
    @override
    @property
    def _command_regex_state(self):
        return {"command": f"show interface ont {self._eltex_serial} state",
                "regex": r"(?:(?P<not_connected>ONT is not connected)|(Equipment ID:\s+(?P<model>[A-Z0-9-]+).*State:\s+(?P<state>[A-Z]+).*RSSI:\s+(?P<rssi>-\d+\.\d+)))"}

    # include flag for ntu1 while parsing get_state match
    @override
    def _parse_get_state_match(self, match):
        self.__ntu1 = match.group("model") == "NTU-1"
        return super()._parse_get_state_match(match)[:-1] + (self.__ntu1,)
    
    # command and regex for get_service_profile_config
    @override
    @property
    def _command_regex_service_profile_config(self):
        return {"command": f"show interface ont {self._eltex_serial} configuration",
                "regex": r"Service \[0\]:\s+(?:\[T\])?\s+Profile cross connect:\s+(?P<service>\S+)"}

    # for ntu1, return another regex to find vlan id
    @override
    @property
    def _regex_configured_vlan_id(self):
        return r"NTU1_(?P<vlan>\d{4})" if self.__ntu1 else super()._regex_configured_vlan_id

    # command and regex for get_log, adding command
    @override
    @property
    def _command_regex_log(self):
        data = super()._command_regex_log
        data["command"] = f"show interface ont {self._eltex_serial} connections"
        return data
    
    # command and regex for get_ports
    @override
    @property
    def _command_regex_ports(self):
        pass
    
    # command and regex for get_mac_addresses
    @override
    @property
    def _command_regex_mac_addresses(self):
        pass
    