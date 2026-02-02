#!/usr/bin/python3
from enum import StrEnum


##### CLASS FOR ERRORS' CODES #####

class ExceptionType(StrEnum):
    # base message
    BASE: str = "Невозможно продиагностировать "

    # city
    NO_SWITCH_PORT: str = "L2: нет свитча и порта"

    SWITCH_NOT_AVAILABLE: str = "L2: свитч недоступен"
    SWITCH_FREEZES: str = "L2: свитч зависает"
    SWITCH_CANNOT_CONNECT: str = "L2: не удаётся подключиться к свитчу, свитч пингуется"

    UNKNOWN_MODEL: str = "L2: неизвестная модель свитча с IP "

    PORT_OUTSIDE_OF_PORTLIST: str = "L2: порт пользователя вне диапазона портов свитча"

    NO_SUBNET: str = "ACL, VLAN и ARP: нет корректных настроек IP"

    # country
    COUNTRY_ALARM_NOT_AVAILABLE: str = "L2: деревенская алярма недоступна"
    ONT_CONFIG_NOT_FOUND: str = "L2: конфиг ONT для юзера не найден"
    SEVERAL_ONT_CONFIGS: str = "L2: несколько конфигов ONT для юзера"
    UNKNOWN_OLT_IP: str = "L2: неизвестный IP-адрес бошки"

    OLT_NOT_AVAILABLE: str = "L2: бошка недоступна"
    OLT_FREEZES: str = "L2: бошка зависает"
    OLT_CANNOT_CONNECT: str = "L2: не удаётся подключиться к бошке, бошка пингуется"

    ONT_NOT_FOUND: str = "L2: ONT не найден"

    CANNOT_CHECK_ACS_MODE: str = "acs-profile и acs-ont: нет корректных настроек IP"
    ACS_PROFILE_NOT_FOUND: str = "acs-profile: не найден"
    ACS_ONT_NOT_FOUND: str = "acs-ont: не найден"


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
    
    # for city, check if it's subnet error
    def is_subnet_error(self):
        return self.__message == ExceptionType.NO_SUBNET
    
    # for country, check if it's no acs mode error
    def is_cannot_check_acs_mode_error(self):
        return self.__message == ExceptionType.CANNOT_CHECK_ACS_MODE
    
    # for country, check if it's acs profile mode error
    def is_acs_profile_mode_error(self):
        return self.__message == ExceptionType.ACS_PROFILE_NOT_FOUND
    
    # for country, check if it's acs ont mode error
    def is_acs_ont_mode_error(self):
        return self.__message == ExceptionType.ACS_ONT_NOT_FOUND
    