#!/usr/bin/python3
from __future__ import annotations
import pexpect
import re
import os
from typing import override
# user's modules
from const import CitySwitch
from base_network_device import BaseNetworkDevice
from my_exception import ExceptionType, MyException
import commands


##### BASE CLASS FOR L2-L3 SWITCHES #####

class BaseSwitch(BaseNetworkDevice):
    __USERNAME: str
    __PASSWORD: str
    _model: str
    __default_gateway: str
    __turn_clipaging: commands.CommandRegexData

    # init by ip and connect with the same username and password
    def __init__(self, ipaddress: str, device_type_name: str, print_output: bool) -> None:
        # get connection's environment
        self.__USERNAME = os.getenv("NET_USER")
        self.__PASSWORD = os.getenv("NET_PASSWORD")

        # switch model name and default gateway
        self._model = ""
        self.__default_gateway = ""   # for d-link, is used only in base class

        # dict to store commands for clipaging
        self.__turn_clipaging = {}
        
        # run base constructor with device type name
        super().__init__(ipaddress, device_type_name, print_output)
    
    # trying to connect by telnet
    @override
    def _connection_attempt(self) -> None:
        self._session = pexpect.spawn(f"telnet {self._ipaddress}", timeout=5, logfile=self._output)
        self._session.expect("(U|u)ser(N|n)ame:")

    # perform base actions after connecting
    @override
    def _enter_action(self) -> None:
        # login
        self._session.sendline(self.__USERNAME)
        self._session.expect("(P|p)ass(W|w)ord:")
        self._session.sendline(self.__PASSWORD)
        self._session.expect("#")
        
        # get through two types of cli to get switch model
        for cli_type in CitySwitch.CLI_TYPES:
            self.__get_model(cli_type)
            if self._model:
               break
        
        # exception if model unknown
        else:
            raise MyException(ExceptionType.UNKNOWN_MODEL, self._ipaddress)

        # turn off clipaging to see commands' whole results
        self.__turn_clipaging = commands.clipaging(self._model)
        self._turn_off_clipaging()
    
    # method to generate exceptions for switches
    @override
    def _get_exception_type(self, error: str) -> ExceptionType:
        return getattr(ExceptionType, f"SWITCH_{error}")
    
    # try to figure out switch model name
    def __get_model(self, cli_type: str) -> None:
        # try to show model info
        command_regex = commands.show_model(cli_type)
        self._session.sendline(command_regex["command"])
        
        # expect output's ending or continuation  and try to find device model
        index = self._session.expect(["CTRL", "#"])
        match = re.search(command_regex["regex"], self._session.before.decode("utf-8"), re.DOTALL)
        
        # quit if needed
        if index == 0:
            self._quit_output()
        
        # catch model if found
        if match:
            # if model unknown, quit
            if match.group("model") not in commands.SWITCHES:
                raise MyException(ExceptionType.UNKNOWN_MODEL, self._ipaddress)
            
            # define model otherwise
            self._model = match.group("model")
            
            # for d-link, define default_gateway, so as not to check it later
            if self._model != commands.CISCO_SWITCH:
                self.__default_gateway = match.group("default_gateway")
    
    # perform exit actions
    @override
    def _exit_action(self) -> None:
        # for d-link, restore clipaging on switch
        if self._model != commands.CISCO_SWITCH:
            self._turn_on_clipaging()
    
    # disable clipaging
    def _turn_off_clipaging(self) -> None:
        self._session.sendline(self.__turn_clipaging["disable"])
        self._session.expect("#")

    # enable clipaging
    def _turn_on_clipaging(self) -> None:
        self._session.sendline(self.__turn_clipaging["enable"])
        self._session.expect("#")
    
    # quit long output with escape symbol
    def _quit_output(self) -> None:
        self._session.send("q")
        self._session.expect("#")
    
    # get default gateway variable
    def get_default_gateway(self) -> str:
        return self.__default_gateway