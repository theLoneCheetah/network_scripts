#!/usr/bin/python3
import pexpect
import re
import sys
import os
from abc import ABC
from icmplib import ping
# user's modules
from const import CONST
from my_exception import ExceptionType, MyException
import commands


##### ABSTRACT CLASS FOR L2-L3 MANAGERS #####

class NetworkManager(ABC):
    # init by ip and connect with the same username and password
    def __init__(self, ipaddress):
        # define ip and get connection's environment
        self.__ipaddress = ipaddress
        self.__USERNAME = os.getenv("NET_USER")
        self.__PASSWORD = os.getenv("NET_PASSWORD")
        
        # switch model name from the defined dict and commands for clipaging
        self._model = ""
        self._ports = 0
        self.__default_gateway = ""   # for d-link, is used only in base class
        self._turn_clipaging = {}
        
        # connect
        self.__start_connection()
    
    # check switch availability by 4 icmp packets and return packet loss
    def __check_ping(self):
        host_data = ping(self.__ipaddress, count=4, timeout=1, interval=0.25, privileged=False)
        return int(host_data.packet_loss)

    # try to figure out switch model name
    def __get_model(self, cli_type):
        # try to show mode info
        command_regex = commands.show_model(cli_type)
        self._session.sendline(command_regex["command"])
        
        # expect output's ending or continuation  and try to find device model
        index = self._session.expect(["CTRL", "#"])
        match = re.search(command_regex["regex"], self._session.before.decode("utf-8"), re.DOTALL)
        
        # quit if needed
        if index == 0:
            self._session.send("q")
            self._session.expect("#")
        
        # catch model if found
        if match:
            # if model unknown, quit
            if match.group("model") not in commands.switches:
                raise MyException(ExceptionType.UNKNOWN_MODEL, self.__ipaddress)
            
            # define model otherwise
            self._model = match.group("model")
            
            # for d-link, define default_gateway, so as not to check it later
            if self._model != commands.cisco_switch:
                self.__default_gateway = match.group("default_gateway")
    
    # start
    def __start_connection(self):
        print("Connecting to equipment...")
        
        # try connecting to switch
        try:
            # protected atribute, it will be inherited
            self._session = pexpect.spawn(f"telnet {self.__ipaddress}")#, logfile=sys.stdout.buffer, timeout=5)
            self._session.expect("(U|u)ser(N|n)ame:", timeout=3)
        # if timeout or another connection error, get packet loss by pinging switch address
        except:
            print("Failed")
            ping_result = self.__check_ping()

            # not available if 100% loss
            if ping_result == 1:
                raise MyException(ExceptionType.SWITCH_NOT_AVAILABLE)
            # freezing/lagging if >0% loss
            elif ping_result > 0:
                raise MyException(ExceptionType.SWITCH_FREEZES)
            # try reconnect if 0% loss
            else:
                # close old session
                self._session.close()
                
                # try connecting again
                try:
                    print("Connecting to equipment...")
                    self._session = pexpect.spawn(f"telnet {self.__ipaddress}", logfile=sys.stdout.buffer, timeout=5)
                    self._session.expect("(U|u)ser(N|n)ame:", timeout=3)
                # can't connect if timeout repeatedly
                except:
                    raise MyException(ExceptionType.SWITCH_CANNOT_CONNECT)

        
        self._session.sendline(self.__USERNAME)
        self._session.expect("(P|p)ass(W|w)ord:")
        self._session.sendline(self.__PASSWORD)
        self._session.expect("#")
        
        # get through two types of cli to get device model
        for cli_type in CONST.cli_types:
            self.__get_model(cli_type)
            if self._model:
               break
        # exception if model unknown
        else:
            raise MyException(ExceptionType.UNKNOWN_MODEL, self.__ipaddress)

        # turn off clipaging to see commands' whole results
        self._turn_clipaging = commands.clipaging(self._model)
        self._session.sendline(self._turn_clipaging["disable"])
        self._session.expect("#")
        
        print("Success")

    def get_default_gateway(self):
        return self.__default_gateway
    
    # end
    def __close_connection(self):
        print("Closing connection...")
        
        # for d-link, restore clipaging on switch if command is known (if unknown, it means that error occured while connecting to switch)
        if self._turn_clipaging and self._model != commands.cisco_switch:
            self._session.sendline(self._turn_clipaging["enable"])
            self._session.expect("#")
        
        self._session.close()
        print("Success")
    
    # delete
    def __del__(self):
        self.__close_connection()