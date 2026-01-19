#!/usr/bin/python3
import pexpect
import re
import sys
import os
from abc import ABC
from icmplib import ping
# user's modules
from const import CitySwitch
from my_exception import ExceptionType, MyException
import commands


##### ABSTRACT CLASS FOR L2-L3 MANAGERS #####

class NetworkManager(ABC):
    # init by ip and connect with the same username and password
    def __init__(self, ipaddress: str, switch_layer_type: str) -> None:
        # define ip
        self._ipaddress = ipaddress

        # indicates if switch is L2 or L3 layer, is used for output while starting and closing connection
        self.__switch_layer_type = switch_layer_type

        # get connection's environment
        self.__USERNAME = os.getenv("NET_USER")
        self.__PASSWORD = os.getenv("NET_PASSWORD")

        # switch model name and default gateway
        self._model = ""
        self.__default_gateway = ""   # for d-link, is used only in base class

        # dict to store commands for clipaging
        self.__turn_clipaging: commands.CommandRegexData = {}
        
        # connect
        self.__start_connection()
    
    # delete, close connection
    def __del__(self) -> None:
        # if clipaging variable is empty, switch connection is not opened, it's nothing to close
        if not self.__turn_clipaging:
            return
        
        print(f"Closing connection to {self.__switch_layer_type}...")
        
        # for d-link, restore clipaging on switch if command is known (if unknown, it means that error occured while connecting to switch)
        if self._model != commands.cisco_switch:
            self._turn_on_clipaging()
        
        self._session.close()
        print("Success")
    
    # start
    def __start_connection(self) -> None:
        print(f"Connecting to {self.__switch_layer_type}...")
        
        # try connecting to switch
        try:
            self._session = pexpect.spawn(f"telnet {self._ipaddress}", timeout=5)#, logfile=sys.stdout.buffer)
            self._session.expect("(U|u)ser(N|n)ame:")
        
        # if timeout or another connection error
        except:
            # close old session
            print(f"Failed to connect to {self.__switch_layer_type}")
            self._session.close()

            # get packet loss by pinging switch address
            packet_loss = self.__check_ping()

            # not available if 100% loss
            if packet_loss == 1:
                raise MyException(ExceptionType.SWITCH_NOT_AVAILABLE)
            
            # freezing/lagging if >0% loss
            elif packet_loss > 0:
                raise MyException(ExceptionType.SWITCH_FREEZES)
            
            # if 0% loss
            else:
                # try connecting again
                try:
                    print(f"Connecting to {self.__switch_layer_type}...")
                    self._session = pexpect.spawn(f"telnet {self._ipaddress}", timeout=5)#, logfile=sys.stdout.buffer)
                    self._session.expect("(U|u)ser(N|n)ame:")
                
                # can't connect if timeout repeatedly
                except:
                    print(f"Failed to connect to {self.__switch_layer_type}")
                    self._session.close()
                    raise MyException(ExceptionType.SWITCH_CANNOT_CONNECT)

        self._session.sendline(self.__USERNAME)
        self._session.expect("(P|p)ass(W|w)ord:")
        self._session.sendline(self.__PASSWORD)
        self._session.expect("#")
        
        # get through two types of cli to get device model
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
        
        print("Success")
    
    # check switch availability by 4 icmp packets and return packet loss
    def __check_ping(self) -> float:
        return ping(self._ipaddress, count=4, timeout=1, interval=0.25, privileged=False).packet_loss

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
            if match.group("model") not in commands.switches:
                raise MyException(ExceptionType.UNKNOWN_MODEL, self._ipaddress)
            
            # define model otherwise
            self._model = match.group("model")
            
            # for d-link, define default_gateway, so as not to check it later
            if self._model != commands.cisco_switch:
                self.__default_gateway = match.group("default_gateway")

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