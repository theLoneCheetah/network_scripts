#!/usr/bin/python3
import re
import traceback
import signal
import sys
import os
from abc import ABC
from typing import Any, override
from contextlib import contextmanager
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

class OLTVersion2(BaseOLT):
    def __init__(self, ipaddress: str, eltex_serial: str, print_output: bool) -> None:
        super().__init__(ipaddress, eltex_serial, print_output)
    
    # context manager to enter terminal diagnostics mode
    @override
    @contextmanager
    def terminal_context(self):
        # 
        try:
            yield
        finally:
            pass
    
    # command and regex for get_state
    @override
    @property
    def _command_regex_state(self):
        return {"command": f"show state",
                "regex": r"(?:(?P<not_connected>ONT is not connected)|(State:\s+(?P<state>[A-Z]+).*RSSI:\s+(?P<rssi>-\d+\.\d+)))"}

    # command and regex for get_service_profile_config
    @override
    @property
    def _command_regex_service_profile_config(self):
        pass

    # command and regex for get_log
    @override
    @property
    def _command_regex_log(self):
        pass

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
    