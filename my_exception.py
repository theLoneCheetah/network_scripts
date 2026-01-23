#!/usr/bin/python3
from enum import StrEnum


##### CLASS FOR ERRORS' CODES #####

class ExceptionType(StrEnum):
    BASE: str = "Невозможно продиагностировать "

    NO_SWITCH_PORT: str = "L2: нет свитча и порта"

    SWITCH_NOT_AVAILABLE: str = "L2: свитч недоступен"
    SWITCH_FREEZES: str = "L2: свитч зависает"
    SWITCH_CANNOT_CONNECT: str = "L2: не удаётся подключиться к свитчу, свитч пингуется"

    UNKNOWN_MODEL: str = "L2: неизвестная модель свитча с IP "

    PORT_OUTSIDE_OF_PORTLIST: str = "L2: порт пользователя вне диапазона портов свитча"

    NO_SUBNET: str = "ACL, VLAN и ARP: нет корректных настроек IP"


##### CLASS FOR USER'S EXCEPTION AND ERRORS' CODES #####

class MyException(Exception):
    __message: str
    __arg: str
    
    # init by base init and message
    def __init__(self, message: ExceptionType, arg: str = ""):
        super().__init__()
        
        # save message, add ip argument if unknown model error
        self.__message = message.value
        self.__arg = arg

    # print with base and specific messages concatenated
    def __str__(self) -> str:
        return ExceptionType.BASE.value + self.__message + self.__arg