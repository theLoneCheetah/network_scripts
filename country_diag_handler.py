#!/usr/bin/python3
import re
import traceback
import signal
import sys
import os
from abc import ABC
from typing import Any, override
from ipaddress import IPv4Address, IPv4Network, AddressValueError
# user's modules
from diag_handler import DiagHandler
from database_manager import DatabaseManager
from L2_manager import L2Manager
from L3_manager import L3Manager
from const import Database, Country
from country_alarm import CountryAlarmManager
from my_exception import ExceptionType, MyException


##### MAIN CLASS TO HANDLE COUNTRY USER DIAGNOSTICS #####

class CountryDiagHandler(DiagHandler):
    # annotations of inherited attributes
    _switch_manager: Any | None
    _gateway_manager: L3Manager | None
    # class attributes annotations
    __print_output: bool
    __ip_correct: bool
    __ip_out_of_country_subnets: bool
    __olt_ip: str
    __eltex_serial: str
    __alarm_usernum_not_found: bool
    __alarm_several_eltex_found: int

    def __init__(self, usernum: int, db_manager: DatabaseManager, record_data: dict[str, Any], inactive_payment: bool, print_output: bool = True) -> None:
        # init with base constructor
        super().__init__(usernum, db_manager, record_data, inactive_payment)

        # L2 and L3 managers
        self._switch_manager = None
        self._gateway_manager = None

        # indicate if terminal output needed
        self.__print_output = print_output


        # attributes for diagnostics of the database record

        # -1 if data from record is incorrect, 0 if empty, 1 if correct
        self._correctly_filled = {}
        
        # flag for main record diagnostics
        self.__ip_correct = False

        # flags for errors in diagnostics of the database record
        self.__ip_out_of_country_subnets = False

        # flags for variables and erros in country alarm
        self.__olt_ip = ""
        self.__eltex_serial = ""
        self.__alarm_usernum_not_found = False
        self.__alarm_several_eltex_found = 0
    

    ##### DATABASE AND USER CARD PART #####
    
    # function to control user's database record checking
    @override
    def _check_user_card(self) -> None:
        try:
            # check and make a note about all unnecessary fields
            for field in Country.UNUSED_NUMBER_FIELDS:
                self._correctly_filled[field] = self.__check_unused_number_fields(field)
            for field in Country.UNUSED_IP_FIELDS:
                self._correctly_filled[field] = self.__check_unused_ip_fields(field)
            
            # check if nnet and nserv fields are strictly correct
            for field in Country.NUMBER_FIELDS:
                self._correctly_filled[field] = self.__check_nserv_nnet(field)
            
            # check ip fields
            for field in Country.IP_FIELDS:
                self._correctly_filled[field] = self._check_ip_fields(field)
            
            # if ip exists, check it
            if self._correctly_filled["ip"] == 1:
                # check for double ip
                self._check_double_ip()

                # error flag if ip is not in country subnets
                if not self.__check_country_ip():
                    self.__ip_out_of_country_subnets = True
                
                # if public ip exists
                elif self._correctly_filled["public_ip"] == 1:
                    # error flag if ip and public ip differ
                    if self._record_data["ip"] != self._record_data["public_ip"]:
                        self._different_ip_public_ip = True
                    # otherwise, ip settings are correct
                    else:
                        self.__ip_correct = True

        except Exception:   # exception while checking record
            print("Exception while working with the database record:")
            traceback.print_exc()
        
        finally:   # always close connection and delete database manager
            del self._db_manager

    # check unused number record fields if empty: port, dhcp
    def __check_unused_number_fields(self, field: str) -> int:
        return 1 if not self._record_data[field] else -1

    # check unused ip record fields if empty: mask, gateway, switch
    def __check_unused_ip_fields(self, field: str) -> int:
        return 1 if not self._record_data[field] else -1

    # check if nserv and nnet match country
    def __check_nserv_nnet(self, field: str) -> int:
        if self._record_data[field] == 0:
            return 0
        elif self._record_data[field] == Country.NSERV_NNET:
            return 1
        return -1

    # check if ip or public_ip are correct
    def __check_country_ip(self) -> bool:
        return any(IPv4Address(self._record_data["ip"]) in subnet for subnet in Country.SUBNETS)
    
    # result of database record diagnostics
    @override
    def _result_user_card(self) -> None:
        # flag to monitor if all diagnostics are ok
        all_correct = True

        # if payment is inactive
        if self._inactive_payment:
            print("Неактивный взнос:", self._record_data["payment"])
            all_correct = False
        
        # print empty fields that should be filled
        if any(value == 0 for value in self._correctly_filled.values()):
            print("Не заполнены поля:", ", ".join(name for key, name in Database.KEY_OUTPUT.items() if self._correctly_filled[key] == 0))
            all_correct = False
        
        # print obviously incorrect fields
        if any(value == -1 for value in self._correctly_filled.values()):
            print("Неверно заполнены поля:", ", ".join(name for key, name in Database.KEY_OUTPUT.items() if self._correctly_filled[key] == -1))
            all_correct = False
        
        # double port and ip
        if self._double_ip:
            print("Дубль айпи:", ", ".join(map(str, self._double_ip)))
            all_correct = False
        
        # ip address errors
        if self.__ip_out_of_country_subnets:
            print("Айпи вне деревенских подсетей")
        elif self._different_ip_public_ip:
            print("Поле Внешний IP не совпадает с IP")
        # if everythin is OK and there was no errors before
        elif all_correct:
            print("OK")
    
    
    ##### L2 AND L3 EQUIPMENT DIAGNOSTICS PART #####

    # function to control diagnosing L2 and L3
    @override
    def _check_L2_L3(self) -> None:
        # get data for olt diagnostics
        self.__get_olt_eltex()

    # get olt and eltex from country alarm for further diagnostics
    def __get_olt_eltex(self) -> None:
        # catch list of matches
        olt_eltex = CountryAlarmManager.get_user_data_from_alarm(self._usernum)

        match len(olt_eltex):
            # error flag if not found
            case 0:
                self.__alarm_usernum_not_found = True
            # save olt and eltex if exactly one found
            case 1:
                self.__olt_ip, self.__eltex_serial = olt_eltex[0]
            # error flag if more than one found
            case _:
                self.__alarm_several_eltex_found = True
    
    # check mac addresses and get as a set
    @override
    def _check_mac(self) -> None:
        pass
    
    # find actual gateway and create L3 manager
    @override
    def _find_actual_gateway(self) -> None:
        pass
    
    # check if vlan's ip interface on L3 matches user's subnet
    @override
    def _check_vlan_subnet(self) -> None:
        pass
    
    # result of L2 and L3 diagnostics
    @override
    def _result_L2_L3(self) -> None:
        # alarm check: no user or sereval onts
        if self.__alarm_usernum_not_found:
            print("Конфиг ONT для юзера не найден")
        elif self.__alarm_several_eltex_found:
            print("Несколько конфигов ONT для юзера")
        else:
            print(self.__olt_ip, self.__eltex_serial)