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
from datetime import datetime
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
    
    # base prompt symbol if different for two versions
    @property
    @abstractmethod
    def _base_prompt(self):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")

    # trying to connect by ssh
    @override
    def _connection_attempt(self):
        # try to login with big timeout
        self._session = pexpect.spawn(f"ssh {self.__USERNAME}@{self._ipaddress}", timeout=10, logfile=self._output)
        self._session.expect("Password:")
        self._session.sendline(self.__PASSWORD)
        self._session.expect(self._base_prompt)

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
        # just return control by default
        try:
            yield
        
        # if eof or timeout during terminal check, ont freezes error
        except (pexpect.EOF, pexpect.TIMEOUT):
            raise MyException(ExceptionType.ONT_FREEZES)
        
        # nothing to do by default in the end
        finally:
            pass
    
    # get ont state and parse main info
    def get_state(self):
        # command
        self._session.sendline(self._command_regex_state["command"])
        self._session.expect(self._base_prompt)

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
        rssi = float(match.group("rssi")) if match.group("rssi") else None

        # by default, it isn't ntu1
        return ont_not_connected, state_error, rssi, False
    
    # check ont service profile config
    def get_service_profile_config(self, ont_not_connected):
        # command
        self._session.sendline(self._command_regex_service_profile_config["command"])
        self._session.expect(self._base_prompt)

        # regex
        temp = self._session.before.decode("utf-8")
        match = re.search(self._command_regex_service_profile_config["regex"], temp, re.DOTALL)

        # parse match and return results
        return self._parse_get_service_profile_config_match(match.group("service"), ont_not_connected)
    
    # command and regex for get_service_profile_config
    @property
    @abstractmethod
    def _command_regex_service_profile_config(self):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    # regex to find vlan id from profile service output, basically a 4-digit number
    @property
    def _regex_configured_vlan_id(self):
        regex = r"(?P<vlan>\d{4})"
        return {"main": regex,
                "reserve": regex}
    
    # parsing get_service_profile_config match object to get vlan, basically without checking for ntu-1
    def _parse_get_service_profile_config_match(self, match, ont_not_connected):
        # get vlan id from config with specialized regex
        match_vlan = re.fullmatch(self._regex_configured_vlan_id["main"], match)

        # return vlan id or None if not found, also False for ntu-1 by default
        return int(match_vlan.group("vlan")) if match_vlan else None, False

    # get connections and check last state and ont flapping
    def get_log(self, state_ok):
        # command
        self._session.sendline(self._command_regex_log["command"])
        self._session.expect(self._base_prompt)

        # regex
        temp = self._session.before.decode("utf-8")
        match = re.search(self._command_regex_log["regex"], temp, re.DOTALL)

        # return None if no log history found
        if not match:
            return None

        # if last state is not ok, return it
        if not state_ok or match.group("last_state") != "Working":
            return match.group("last_state")
        
        # otherwise catch all connections log datetimes to ckeck flapping
        matches = re.findall(self._command_regex_log["findall"], temp)
        match_datetimes = [datetime.strptime(f"{date} {time}", self._command_regex_log["format"]) for date, time in matches]

        # return count of those records that are in last minutes' range
        current_datetime = datetime.now()
        return len([dt for dt in match_datetimes if (current_datetime - dt).total_seconds() // 60 <= Country.MAX_MINUTE_RANGE_ONT_FLAPPING])

    # command and regex for get_log, command should be overridden
    @property
    @abstractmethod
    def _command_regex_log(self):
        return {"format": "%Y-%m-%d %H:%M:%S",
                "regex": r".*Last state :\s+(?P<last_state>[A-Za-z ]+)",
                "findall": r"LinkUp :\s+(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})"}
    
    # get active ports info 
    def get_ports(self):
        # command
        self._session.sendline(self._command_regex_ports["command"])
        self._session.expect(self._base_prompt)

        # regex
        temp = self._session.before.decode("utf-8")
        match = re.search(self._command_regex_ports["regex"], temp, re.DOTALL)

        # return None if not found
        if not match:
            return None

        # list of dictionaries to store active ports data
        ports_link_up = []
        
        # for each active port, save its speed and duplex
        for port, link, speed, duplex in zip(*[group.split() for group in match.group("port", "link", "speed", "duplex")]):
            if link == "up":
                # replace some speed symbols if needed
                ports_link_up.append({"port": int(port), "speed": self._ports_speed_replace_operation(speed), "duplex": duplex})
        
        # return final active ports list
        return ports_link_up

    # command and regex for get_ports, regex is common
    @property
    @abstractmethod
    def _command_regex_ports(self):
        return {"regex": fr"UNI ##(?P<port>(?:\s+\d){{{self._ports_count}}})\s+Link:(?P<link>(?:\s+\S+){{{self._ports_count}}})\s+Speed:(?P<speed>(?:\s+\S+){{{self._ports_count}}})\s+Duplex:(?P<duplex>(?:\s+\S+){{{self._ports_count}}})"}
    
    # get ont ports count
    @property
    def _ports_count(self):
        return 4

    # replace some symbols in ont ports' speed output if needed
    def _ports_speed_replace_operation(self, speed):
        return speed

    # get mac addresses and return as a set, method is used for L2Protocol
    def get_mac_addresses(self) -> set[str]:
        # command
        self._session.sendline(self._command_regex_mac_addresses["command"])
        self._session.expect(self._base_prompt)

        # regex
        temp = self._session.before.decode("utf-8")
        mac_addresses = set()

        # for each found mac address, replace : with - for standard view
        for match in re.finditer(self._command_regex_mac_addresses["regex"], temp):
            mac_addresses.add(match.group("mac").replace(":", "-"))
        
        # return set of macs
        return mac_addresses
    
    # command and regex for get_mac_addresses, regex is common
    @property
    @abstractmethod
    def _command_regex_mac_addresses(self):
        return {"regex": r"(\d+)\s+(?P<mac>(?:[A-Z\d]{2}:){5}[A-Z\d]{2})"}
    
    # context manager for acs mode
    @contextmanager
    def acs_context(self):
        try:
            # enter
            self._session.sendline("acs")
            self._session.expect(r"\(acs\)")
            yield
        
        finally:
            # exit
            self._session.sendline("exit")
            self._session.expect(self._base_prompt)
    
    # context manager for acs-profile mode
    @contextmanager
    def acs_profile_context(self):
        try:
            # enter profile
            self._session.sendline("profile")
            self._session.expect(r"\(acs-profile\)")

            # enter certain profile or catch message if profile not found
            self._session.sendline(f"profile {self._eltex_serial}")
            index = self._session.expect([fr"\(acs-profile-name='{self._eltex_serial}'\)", "not found"])

            # raise exception if profile not found
            if index == 1:
                raise MyException(ExceptionType.ACS_PROFILE_NOT_FOUND)
            
            yield
        
        finally:
            # first exit, expect acs-profile or acs mode
            self._session.sendline("exit")
            index = self._session.expect([r"\(acs-profile\)", r"\(acs\)"])

            # second exit if in acs-profile mode
            if index == 0:
                self._session.sendline("exit")
                self._session.expect(r"\(acs\)")
    
    # get acs profile config and base profile name
    def get_acs_profile_config(self):
        # command
        self._session.sendline(self._command_regex_acs_profile_config["command"])
        self._session.expect(r"\)")

        # regex
        temp = self._session.before.decode("utf-8")
        match = re.search(self._command_regex_acs_profile_config["regex"], temp, re.DOTALL)

        # catch base acs profile name: default, bridge or no base profile
        acs_profile_type = None
        if match.group("default"):
            acs_profile_type = "default"
        elif match.group("bridge"):
            acs_profile_type = "bridge"
        
        # return base profile
        return acs_profile_type

    # command and regex for get_acs_profile_config, command is common
    @property
    @abstractmethod
    def _command_regex_acs_profile_config(self):
        return {"command": "show config"}
    
    # get acs profile property, vlan and ip settings
    def get_acs_profile_property(self):
        # command
        self._session.sendline(self._command_regex_acs_profile_property["command"])
        self._session.expect(r"\)")

        # regex
        temp = self._session.before.decode("utf-8")
        regex = re.compile(self._command_regex_acs_profile_property["regex"])

        # dict to store results
        res = {key: None for key in regex.groupindex}

        # find by finditer as profile strings can be in different order
        for match in regex.finditer(temp, re.DOTALL):
            for key, val in match.groupdict().items():
                # save existing groups, convert vlan to int
                if val:
                    res[key] = int(val) if key == "vlan" else val

        # return all found/not found settings: vlan, ip, mask, gateway
        return (res[key] for key in regex.groupindex)

    # command and regex for get_acs_profile_property
    @property
    def _command_regex_acs_profile_property(self):
        prefix = r'Name = "InternetGatewayDevice\.WANDevice\.5\.WANConnectionDevice\.1\.WANIPConnection\.1\.'
        return {"command": "show property",
                "regex": (fr'{prefix}X_BROADCOM_COM_VlanMuxID"\s+Value = "(?P<vlan>\d{{4}})"'
                          fr'|{prefix}ExternalIPAddress"\s+Value = "(?P<ip>(?:\d{{1,3}}\.){{3}}\d{{1,3}})"'
                          fr'|{prefix}SubnetMask"\s+Value = "(?P<mask>(?:\d{{1,3}}\.){{3}}\d{{1,3}})"'
                          fr'|{prefix}DefaultGateway"\s+Value = "(?P<gateway>(?:\d{{1,3}}\.){{3}}\d{{1,3}})"')}
    
    # context manager for acs-ont mode
    @contextmanager
    def acs_ont_context(self):
        try:
            # enter ont
            self._session.sendline("ont")
            self._session.expect(r"\(acs-ont\)")

            # enter certain ont or catch message if ont not found
            self._session.sendline(f"ont {self._eltex_serial}")
            index = self._session.expect([fr"\(acs-ont-sn='{self._eltex_serial}'\)", "not found"])

            # raise exception if profile not found
            if index == 1:
                raise MyException(ExceptionType.ACS_ONT_NOT_FOUND)
            
            yield
        
        finally:
            # first exit, expect acs-ont or acs mode
            self._session.sendline("exit")
            index = self._session.expect([r"\(acs-ont\)", r"\(acs\)"])

            # second exit if in acs-ont mode
            if index == 0:
                self._session.sendline("exit")
                self._session.expect(r"\(acs\)")
    
    # get acs ont full config
    def get_acs_ont(self):
        # command
        self._session.sendline(self._command_regex_acs_ont["command"])
        self._session.expect(r"\)")

        # regex
        temp = self._session.before.decode("utf-8")
        match = re.search(self._command_regex_acs_ont["regex"], temp, re.DOTALL)

        # return True if profile with the same eltex serial is set for this ont
        return match is not None

    # command and regex for get_acs_ont
    @property
    def _command_regex_acs_ont(self):
        return {"command": "show full",
                "regex": f"Profile '{self._eltex_serial}'"}
    