#!/usr/bin/python3
import re
import traceback
import signal
import sys
import os
from abc import ABC
from typing import override
from ipaddress import IPv4Address, IPv4Network, AddressValueError
# user's modules
from diag_handler import DiagHandler
from database_manager import DatabaseManager
from L2_manager import L2Manager
from L3_manager import L3Manager
from const import Const
from my_exception import ExceptionType, MyException


##### MAIN CLASS TO HANDLE COUNTRY USER DIAGNOSTICS #####

class CountryDiagHandler(DiagHandler):
    def __init__(self, usernum, db_manager, record_data, inactive_payment):
        # init with base constructor
        super().__init__(usernum, db_manager, record_data, inactive_payment)

        # L2 and L3 managers
        self._switch_manager = None
        self._gateway_manager = None


        # attributes for diagnostics of the database record

        # -1 if data from record is incorrect, 0 if empty, 1 if correct
        self._correctly_filled = {}
    

    ##### DATABASE AND USER CARD PART #####
    
    # function to control user's database record checking
    @override
    def _check_user_card(self):
        try:
            # check and make a note about all unnecessary fields
            for field in Const.COUNTRY_UNUSED_NUMBER_FIELDS:
                self._correctly_filled[field] = self.__check_unused_number_fields(field)
            for field in Const.COUNTRY_UNUSED_IP_FIELDS:
                self._correctly_filled[field] = self.__check_unused_ip_fields(field)
            
            # check if nnet and nserv fields are strictly correct
            for field in {"nserv", "nnet"}:
                self._correctly_filled[field] = self.__check_nserv_nnet(field)
            
            # check ip fields
            for field in {"ip", "public_ip"}:
                self._correctly_filled[field] = self.__check_country_ip(field)
            
            # different ip and public ip: base flag?

        except Exception as err:   # exception while checking record
            print("Exception while working with the database record:", traceback.print_exc(), sep="\n")
        
        finally:   # always close connection and delete database manager
            del self._db_manager

    # check unused number record fields if empty: port, dhcp
    def __check_unused_number_fields(self, field):
        return 1 if self._record_data[field] == None or self._record_data[field] == 0 else -1

    # check unused ip record fields if empty: mask, gateway, switch
    def __check_unused_ip_fields(self, field):
        return 1 if self._record_data[field] == None else -1

    # check if nserv and nnet match country
    def __check_nserv_nnet(self, field):
        return 1 if self._record_data[field] == Const.COUNTRY_NSERV_NNET else -1

    # check if ip or public_ip are not empty and match country direct public ip subnets
    def __check_country_ip(self, field):
        if not self._record_data[field]:
            return 0
        try:
            if IPv4Address(self._record_data[field]) in Const.COUNTRY_SUBNETS:
                return 1
            return -1
        except AddressValueError:
            return -1

    # result of database record diagnostics
    @override
    def _result_user_card(self):
        all_correct = True

        # if payment is inactive
        if self._inactive_payment:
            print("Неактивный взнос:", self._record_data["payment"])
            all_correct = False
    
    
    ##### L2 AND L3 EQUIPMENT DIAGNOSTICS PART #####

    # function to control diagnosing L2 and L3
    @override
    def _check_L2_L3(self):
        pass
    
    # check mac addresses and get as a set
    @override
    def _check_mac(self):
        pass
    
    # find actual gateway and create L3 manager
    @override
    def _find_actual_gateway(self):
        pass
    
    # check if vlan's ip interface on L3 matches user's subnet
    @override
    def _check_vlan_subnet(self):
        pass
    
    # result of L2 and L3 diagnostics
    @override
    def _result_L2_L3(self):
        pass
    