#!/usr/bin/python3
from enum import Enum


##### CLASS FOR ERRORS' CODES #####

class ExceptionType(Enum):
    BASE = "Unable to diagnose "

    NO_SWITCH_PORT = "L2: don't have switch and port"
    SWITCH_NOT_AVAILABLE = "L2: switch is not available"
    SWITCH_FREEZES = "L2: switch freezes"
    SWITCH_CANNOT_CONNECT = "L2: can't connect to switch"

    UNKNOWN_MODEL = "L2: unknown switch model with ip "

    PORT_OUTSIDE_OF_PORTLIST = "L2: user's port is outside switch's portlist"

    NO_SUBNET = "ACL, VLAN and ARP: don't have correct subnet"

##### CLASS FOR USER'S EXCEPTION AND ERRORS' CODES #####

class MyException(Exception):
    not_connected_values = {err.value for err in (ExceptionType.NO_SWITCH_PORT, ExceptionType.SWITCH_NOT_AVAILABLE,
                                                  ExceptionType.SWITCH_FREEZES, ExceptionType.SWITCH_CANNOT_CONNECT)}
    
    # init by base init and message
    def __init__(self, message, arg=""):
        super().__init__()
        
        # save message, add ip argument if unknown model error
        self.__message = message.value
        self.__arg = arg

    # True if switch not connected
    def is_switch_not_connected_error(self):
        return self.__message in self.not_connected_values
    
    # True is switch model unknown
    def is_switch_unknown_model_error(self):
        return self.__message == ExceptionType.UNKNOWN_MODEL.value

    # print with base and specific messages concatenated
    def __str__(self):
        return ExceptionType.BASE.value + self.__message + self.__arg