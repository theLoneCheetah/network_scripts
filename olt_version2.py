#!/usr/bin/python3
import re
import traceback
import signal
import sys
import os
import pexpect
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
    
    # base prompt symbol
    @override
    @property
    def _base_prompt(self):
        return ">"
    
    # context manager to enter terminal diagnostics mode
    @override
    @contextmanager
    def terminal_context(self):
        # entering manager
        try:
            # enter pon
            self._session.sendline("pon")
            self._session.expect(r"\(pon\)>")

            # enter ont_sn or catch message if ont doesn't exist
            self._session.sendline(f"ont_sn {self._eltex_serial}")
            index = self._session.expect([fr"\(pon/ont-{self._eltex_serial}\)>", "ONT does not exist"])

            # raise exception if ont not found (not exist)
            if index == 1:
                raise MyException(ExceptionType.ONT_NOT_FOUND)
            
            # return control
            yield
        
        # if ont not found, raise special exception
        except (pexpect.EOF, pexpect.TIMEOUT):
            raise MyException(ExceptionType.ONT_NOT_FOUND)
        
        # exiting manager
        finally:
            # first exit, expect pon or main mode
            self._session.sendline("exit")
            index = self._session.expect([r"\(pon\)>", r"[^)]>"])

            # second exit if in pon mode
            if index == 0:
                self._session.sendline("exit")
                self._session.expect(">")
    
    # command and regex for get_state
    @override
    @property
    def _command_regex_state(self):
        return {"command": f"show state",
                "regex": r"(?P<not_connected>ONT is not connected)|(State:\s+(?P<state>[A-Z]+).*RSSI:\s+(?:(?P<rssi>-\d+\.\d+)|(?P<rssi_not_available>N/A)))"}

    # command and regex for get_service_profile_config
    @override
    @property
    def _command_regex_service_profile_config(self):
        return {"command": f"show config",
                "regex": r"Profile services:\s+\d\s+\((?P<service>\S+)\)"}

    # command and regex for get_log, adding command
    @override
    @property
    def _command_regex_log(self):
        data = super()._command_regex_log
        data["command"] = f"show connections"
        return data
    
    # command and regex for get_ports, specify command
    @override
    @property
    def _command_regex_ports(self):
        data = super()._command_regex_ports
        data["command"] = f"show ports"
        return data
    
    # replace some symbols in ont ports' speed output
    @override
    def _ports_speed_replace_operation(self, speed):
        return speed.replace("1G", "1000M")

    # command and regex for get_mac_addresses, specify command
    @override
    @property
    def _command_regex_mac_addresses(self):
        data = super()._command_regex_mac_addresses
        data["command"] = f"show mac"
        return data
    
    # command and regex for get_acs_profile_config, specify regex
    @override
    @property
    def _command_regex_acs_profile_config(self):
        data = super()._command_regex_acs_profile_config
        data["regex"] = r'Base profile = "(?:(?P<default>1402_default)|(?P<bridge>1402_bridge))"'
        return data
    