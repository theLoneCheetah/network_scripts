#!/usr/bin/python3
from __future__ import annotations
import pexpect
import sys
from abc import ABC, abstractmethod
from icmplib import ping
from typing import TYPE_CHECKING
# user's modules
from my_exception import MyException

# import as type only by Pylance (for VS Code)
if TYPE_CHECKING:
    from io import BufferedWriter


##### BASE CLASS FOR ALL NETWORK DEVICES #####

class BaseNetworkDevice(ABC):
    _ipaddress: str
    __device_type_name: str
    _output: BufferedWriter | None
    _session: pexpect.spawn

    # all devices init by ip
    def __init__(self, ipaddress: str, device_type_name: str, print_output: bool) -> None:
        # define ip
        self._ipaddress = ipaddress

        # device layer and type, also session output buffer for output
        self.__device_type_name = device_type_name
        self._output = sys.stdout.buffer if print_output else None

        # connect
        self.__start_connection()
    
    # start
    def __start_connection(self) -> None:
        print(f"Connecting to {self.__device_type_name}...")
        
        # try connecting
        try:
            self._connection_attempt()
        
        # if timeout or another connection error
        except:
            # close old session
            print(f"Failed to connect to {self.__device_type_name}")
            self._session.close()

            # get packet loss by pinging device address
            packet_loss = self.__check_ping()
            
            # not available if 100% loss
            if packet_loss == 1:
                raise MyException(self._get_exception_type("NOT_AVAILABLE"))
            
            # freezing/lagging if >0% loss
            elif packet_loss > 0:
                raise MyException(self._get_exception_type("FREEZES"))
            
            # if 0% loss
            else:
                # try connecting again
                try:
                    print(f"Connecting to {self.__device_type_name}...")
                    self._connection_attempt()
                
                # can't connect if timeout repeatedly
                except:
                    print(f"Failed to connect to {self.__device_type_name}")
                    self._session.close()
                    raise MyException(self._get_exception_type("CANNOT_CONNECT"))
        
        # actions that needed right after connection
        self._enter_action()
        
        print("Success")

    # commands to try connecting to device
    @abstractmethod
    def _connection_attempt(self):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    # commands to perform after connecting
    @abstractmethod
    def _enter_action(self):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    # method to get exception for different device types
    @abstractmethod
    def _get_exception_type(self, error):
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    # check switch availability by 4 icmp packets and return packet loss
    def __check_ping(self) -> float:
        return ping(self._ipaddress, count=4, timeout=1, interval=0.25, privileged=False).packet_loss

    # delete, close connection
    def __del__(self) -> None:
        # if session is not active, it's nothing to close
        if not self._session.isalive():
            return
        
        print(f"Closing connection to {self.__device_type_name}...")
        
        # perform pre-exit actions
        self._exit_action()
        
        self._session.close()
        print("Success")

    # override if necessary to perform commands before closing connection
    def _exit_action(self):
        pass
