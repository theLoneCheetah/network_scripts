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
from const import Country
from my_exception import ExceptionType, MyException


##### MAIN CLASS TO HANDLE COUNTRY USER DIAGNOSTICS #####

class CountryDiagHandler(DiagHandler):
    def __init__(self, usernum: int, db_manager: DatabaseManager, record_data: dict[str, Any], inactive_payment: bool) -> None:
        # init with base constructor
        super().__init__(usernum, db_manager, record_data, inactive_payment)

        # L2 and L3 managers
        self._switch_manager: Any | None = None
        self._gateway_manager: L3Manager | None = None


        # attributes for diagnostics of the database record

        # -1 if data from record is incorrect, 0 if empty, 1 if correct
        self._correctly_filled = {}
    

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
                self._correctly_filled[field] = self.__check_country_ip(field)
            
            # different ip and public ip: base flag?

        except Exception as err:   # exception while checking record
            print("Exception while working with the database record:")
            traceback.print_exc()
        
        finally:   # always close connection and delete database manager
            del self._db_manager

    # check unused number record fields if empty: port, dhcp
    def __check_unused_number_fields(self, field: str) -> int:
        return 1 if self._record_data[field] is None or self._record_data[field] == 0 else -1

    # check unused ip record fields if empty: mask, gateway, switch
    def __check_unused_ip_fields(self, field: str) -> int:
        return 1 if self._record_data[field] is None else -1

    # check if nserv and nnet match country
    def __check_nserv_nnet(self, field: str) -> int:
        return 1 if self._record_data[field] == Country.NSERV_NNET else -1

    # check if ip or public_ip are not empty and match country direct public ip subnets
    def __check_country_ip(self, field: str) -> int:
        if not self._record_data[field]:
            return 0
        try:
            if IPv4Address(self._record_data[field]) in Country.SUBNETS:
                return 1
            return -1
        except AddressValueError:
            return -1

    # result of database record diagnostics
    @override
    def _result_user_card(self) -> None:
        all_correct = True

        # if payment is inactive
        if self._inactive_payment:
            print("Неактивный взнос:", self._record_data["payment"])
            all_correct = False
    
    
    ##### L2 AND L3 EQUIPMENT DIAGNOSTICS PART #####

    # function to control diagnosing L2 and L3
    @override
    def _check_L2_L3(self) -> None:
        pass
    
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
        pass
    