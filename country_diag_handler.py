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
    def __init__(self, usernum, db_manager, record_data):
        # init with base constructor
        super().__init__(usernum, db_manager, record_data)

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
        pass

    # result of database record diagnostics
    @override
    def _result_user_card(self):
        pass
    
    
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
    