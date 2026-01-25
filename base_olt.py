#!/usr/bin/python3
import pexpect
import re
import traceback
import signal
import sys
import os
from abc import ABC, abstractmethod
from typing import Any, override
from contextlib import contextmanager
from icmplib import ping
from ipaddress import IPv4Address, IPv4Network, AddressValueError
# user's modules
from diag_handler import DiagHandler
from database_manager import DatabaseManager
from base_network_device import BaseNetworkDevice
from L2_switch import L2Switch
from L3_switch import L3Switch
from const import Database, Country
from country_alarm import CountryAlarmManager
from my_exception import ExceptionType, MyException


##### BASE CLASS FOR COUNTRY OLT L2 SWITCH #####

class BaseOLT(BaseNetworkDevice):
    _eltex_serial: str
    __USERNAME: str
    __PASSWORD: str

    # init by ip and connect with the same username and password
    def __init__(self, ipaddress: str, eltex_serial: str, print_output: bool) -> None:
        # define ip and user's eltex serial
        self._eltex_serial = eltex_serial

        # get connection's environment
        self.__USERNAME = os.getenv("COUNTRY_USER")
        self.__PASSWORD = os.getenv("NET_PASSWORD")

        # run base constructor with device type name
        super().__init__(ipaddress, "L2 OLT", print_output)
    
    # trying to connect by ssh
    @override
    def _connection_attempt(self):
        # try to login with big timeout
        self._session = pexpect.spawn(f"ssh {self.__USERNAME}@{self._ipaddress}", timeout=10, logfile=self._output)
        self._session.expect("Password:")
        self._session.sendline(self.__PASSWORD)
        self._session.expect(">|#")

    # perform base actions after connecting
    @override
    def _enter_action(self) -> None:
        # set lower timeout for further commands
        self._session.timeout = 5
    
    # method to generate exceptions for olts
    @override
    def _get_exception_type(self, error):
        return getattr(ExceptionType, f"OLT_{error}")
    
    # context manager for working with terminal commands
    @contextmanager
    def terminal_context(self):
        # nothing to do by default
        try:
            yield
        finally:
            pass
    
    # get ont state and parse main info
    def get_state(self):
        # command
        self._session.sendline(self._command_regex_state["command"])
        self._session.expect("#")

        # regex
        temp = self._session.before.decode("utf-8")
        match = re.search(self._command_regex_state["regex"], temp, re.DOTALL)

        # return None if ont not found
        if not match:
            return None
        
        # return parsing result otherwise    
        return self._parse_get_state_match(match)
    
    # command and regex for get_state
    @property
    @abstractmethod
    def _command_regex_state(self):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    # parsing get_state match object
    def _parse_get_state_match(self, match):
        # basically, return not_connected flag, state_error if there is and rssi
        ont_not_connected = match.group("not_connected") is not None
        state_error = match.group("state") if match.group("state") != "OK" else ""
        rssi = float(match.group("rssi")) if match.group("rssi") else 0.0

        # by default, it isn't ntu1
        return ont_not_connected, state_error, rssi, False
    
    def get_service_profile_config(self):
        pass

    # command and regex for get_service_profile_config
    @property
    @abstractmethod
    def _command_regex_service_profile_config(self):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    def get_log(self):
        pass

    # command and regex for get_log
    @property
    @abstractmethod
    def _command_regex_log(self):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    def get_ports(self):
        pass

    # command and regex for get_ports
    @property
    @abstractmethod
    def _command_regex_ports(self):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    def get_mac_addresses(self):
        pass
    
    # command and regex for get_mac_addresses
    @property
    @abstractmethod
    def _command_regex_mac_addresses(self):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    