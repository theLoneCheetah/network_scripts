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
        # expect exactly one # symbol because there're ## constructions in some commands' outputs
        return r"(?<!#)#(?!#)"
    
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

    # basically regex for ntu-1/not, also reserve regex for ntu-1
    @override
    @property
    def _regex_configured_vlan_id(self):
        regex = r"NTU1_(?P<vlan>\d{4})"
        return {"main": regex if self.__ntu1 else super()._regex_configured_vlan_id["main"],
                "reserve": regex}
    
    # parsing get_service_profile_config match object to get vlan, also check reserve regex for ntu-1
    def _parse_get_service_profile_config_match(self, match, ont_not_connected):
        # get base results
        vlan_id, ntu1 = super()._parse_get_service_profile_config_match(match, ont_not_connected)

        # if vlan id was already found or ont is connected (it means that ntu-1/not was checked), return same results
        if vlan_id or not ont_not_connected:
            return vlan_id, ntu1
        
        # otherwise, try to find ntu-1 vlan profile with reserve regex
        match_vlan = re.fullmatch(self._regex_configured_vlan_id["reserve"], match)

        # if found, mark flag for ntu-1
        if match_vlan:
            self.__ntu1 = True
        
        # return vlan id or None if not found, also flag for ntu-1
        return int(match_vlan.group("vlan")) if match_vlan else None, self.__ntu1

    # command and regex for get_log, adding command
    @override
    @property
    def _command_regex_log(self):
        data = super()._command_regex_log
        data["command"] = f"show interface ont {self._eltex_serial} connections"
        return data
    
    # command and regex for get_ports, specify command
    @override
    @property
    def _command_regex_ports(self):
        data = super()._command_regex_ports
        data["command"] = f"show interface ont {self._eltex_serial} ports"
        return data
    
    # get ont ports count, only 1 port for ntu1
    @override
    @property
    def _ports_count(self):
        return 1 if self.__ntu1 else 4

    # command and regex for get_mac_addresses, specify command
    @override
    @property
    def _command_regex_mac_addresses(self):
        data = super()._command_regex_mac_addresses
        data["command"] = f"show mac interface ont {self._eltex_serial}"
        return data
    
    # command and regex for get_acs_profile_config, specify regex
    @override
    @property
    def _command_regex_acs_profile_config(self):
        data = super()._command_regex_acs_profile_config
        data["regex"] = r'Base profile = "(?:(?P<default>1402_default_v2)|(?P<bridge>1402_bridge_v2))"'
        return data
    