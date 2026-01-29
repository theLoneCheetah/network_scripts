#!/usr/bin/python3
from __future__ import annotations
from typing import TYPE_CHECKING, Any
from abc import abstractmethod
import sys
from ipaddress import IPv4Address, AddressValueError
# user's modules
from base_handler import BaseHandler
from database_manager import DatabaseManager
from const import Database, Country

# import as type only by Pylance (for VS Code)
if TYPE_CHECKING:
    from my_exception import MyException
    from L3_switch import L3Switch


##### BASE DIAGNOSTICS HANDLER CLASS #####

class DiagHandler(BaseHandler):
    # annotations of protected attributes
    _inactive_payment: bool
    _different_ip_public_ip: bool
    _double_ip: list[int]
    _L2_exception: MyException | None
    _mac_addresses: set[str]
    _mac_ok: bool
    _no_mac: bool
    _many_macs: int
    _ip_interface_not_found: bool
    _ip_interface_wrong_subnet: bool
    _arp_ok: bool
    _no_arp: bool
    _arp_on_unknown_mac: str
    _ip_incorrect_arp_on_mac: list[str]
    _need_to_check_mac_on_L3: bool
    _no_mac_on_L3: bool
    # annotations of objects in child classes: L3 managers, correctly filled indicator dict
    _L3_manager: L3Switch
    _correctly_filled: dict[str, int]

    def __init__(self, usernum: int, db_manager: DatabaseManager, record_data: dict[str, Any], inactive_payment: bool) -> None:
        # init with base constructor
        super().__init__(usernum)

        # database managers and record data object are be given by child class
        self._db_manager = db_manager
        self._record_data = record_data
        self._inactive_payment = inactive_payment

        # this error is typical for both city and country
        self._different_ip_public_ip = False
        
        # there will be usernums if found doubles, actual for all users
        self._double_ip = []

        # user's exception while working with L2
        self._L2_exception = None
        
        # mac address
        self._mac_addresses = set()
        self._mac_ok = False
        self._no_mac = False
        self._many_macs = 0   # count mac addresses if there's more than 1

        # ip interface on L3
        self._ip_interface_not_found = False
        self._ip_interface_wrong_subnet = False

        # arp
        self._arp_ok = False
        self._no_arp = False
        self._arp_on_unknown_mac = ""   # here wiil be unknown mac if found
        self._ip_incorrect_arp_on_mac = []    # here will be unknown ip addresses if found
        
        # mac check on L3
        self._need_to_check_mac_on_L3 = False
        self._no_mac_on_L3 = False

    # main function
    def check_all(self) -> None:
        # check all functions
        self._check_user_card()
        self._check_L2_L3()
        
        # print user card part
        print("-" * 20)
        print("ДИАГНОСТИКА КАРТОЧКИ:")
        self._result_user_card()
        
        # print L2 and L3 diagnostics part
        print("-" * 20)
        print("ДИАГНОСТИКА ОБОРУДОВАНИЯ:")
        self._result_L2_L3()
    

    ##### DATABASE AND USER CARD PART #####
    
    # function to control user's database record checking
    @abstractmethod
    def _check_user_card(self) -> None:
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    # check ip record fields: ip, mask, gateway, switch, public_ip
    def _check_ip_fields(self, field: str) -> int:
        if not self._record_data[field]:
            return 0
        try:
            IPv4Address(self._record_data[field])
            return 1
        except AddressValueError:
            return -1
    
    # check users with the same ip, return list of doubles if found
    def _check_double_ip(self) -> None:
        usernums = self._db_manager.get_usernum_by_ip(self._record_data["ip"])
        self._double_ip = usernums if len(usernums) > 1 else []

    # result of database record diagnostics
    @abstractmethod
    def _result_user_card(self) -> None:
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    
    ##### L2 AND L3 EQUIPMENT DIAGNOSTICS PART #####

    # function to control diagnosing L2 and L3
    @abstractmethod
    def _check_L2_L3(self) -> None:
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    # base method to check mac addresses and get as a set
    def _check_mac(self) -> None:
        # get set of all mac addresses
        self._mac_addresses = self._L2_manager.get_mac_addresses()
        
        # error when there's no mac, cable diag needed
        if not self._mac_addresses:
            self._no_mac = True
        # error when there're more than 1 mac
        elif len(self._mac_addresses) > 1:
            self._many_macs = len(self._mac_addresses)
        # correct flag if only 1 mac
        else:
            self._mac_ok = True
    
    # find actual gateway and create L3 manager
    @abstractmethod
    def _find_actual_gateway(self) -> None:
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    # check if vlan's ip interface on L3 matches user's subnet
    @abstractmethod
    def _check_vlan_subnet(self) -> None:
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")
    
    # compare subnet from L3 ip interface with subnet from user card
    def _check_user_subnet_matches_ip_interface(self, vlan_id: int, vlan_name: str, ipif_name: str, gateway: str, mask_length: int) -> None:
        # L3 manager checks ipif by vlan and compares with user's subnet
        res = self._L3_manager.check_ip_interface_subnet(vlan_id, vlan_name, ipif_name, gateway, mask_length)
        
        # rarely when ipif doesn't exist or has another name
        if res is None:
            self._ip_interface_not_found = True
        # if ipif's by vlan subnet differs from user's subnet
        elif res == False:
            self._ip_interface_wrong_subnet = True
    
    # check arpentry by ip and mac and try other options on L3
    def _check_arpentry_by_ip(self) -> None:
        # get mac from arp found by ip
        mac = self._L3_manager.check_arpentry_ip_return_mac()
        
        # get ip addresses from arp found by mac
        ips = self._get_ips_from_arpentry_mac()
        
        # found arp by ip and its mac is known
        if mac and mac in self._mac_addresses:
            # mark flag that arp is correct
            self._arp_ok = True
            
            # if found many arps by mac, remember extra ip addresses
            if len(ips) > 1:
                self._ip_incorrect_arp_on_mac = [ip for ip in ips if ip != self._record_data["ip"]]
        
        # if no arp found or arp has unknown mac
        else:
            # record extra ip addresses from arps by mac if have any
            self._ip_incorrect_arp_on_mac = ips
            
            # if arp by ip exists on unknown mac, remember it
            if mac and mac not in self._mac_addresses:
                self._arp_on_unknown_mac = mac
            
            # mark flag if no arp found at all
            self._no_arp = not self._ip_incorrect_arp_on_mac and not self._arp_on_unknown_mac
            
            # if no arp on mac found, check mac reaches L3
            if not self._ip_incorrect_arp_on_mac:
                self._check_mac_visible_on_L3()
    
    # try to check arp on mac if there's only 1 mac
    def _get_ips_from_arpentry_mac(self) -> list[str]:
        # if there's no mac or more than 1, can't find
        if len(self._mac_addresses) != 1:
            return []
        
        # return list of ip addresses with arp on this mac
        return self._L3_manager.check_arpentry_mac_return_ips(*self._mac_addresses)
    
    # check mac visibility on L3 and set a flag if not visible
    def _check_mac_visible_on_L3(self) -> None:
        # if there's no mac or more than 1, can't find
        if len(self._mac_addresses) != 1:
            return
        
        # flag to simplify output control, when mac on L3 info should be displayed
        self._need_to_check_mac_on_L3 = True
        
        # set flag True if no mac found
        self._no_mac_on_L3 = self._L3_manager.check_mac_on_L3(*self._mac_addresses)
    
    # result of L2 and L3 diagnostics
    @abstractmethod
    def _result_L2_L3(self) -> None:
        raise NotImplementedError(f"Method {sys._getframe(0).f_code.co_name} not implemented in child class")

    ##### BASE FIRST CHECK PART #####

    # static method to get main data from database and decide country or not
    @staticmethod
    def decide_country_or_city(usernum: int) -> tuple[bool, DatabaseManager, dict[str, Any], bool]:
        def check_country_or_city(payment, nnet):
            if (payment in Database.COUNTRY_PAYMENT or nnet == Country.NSERV_NNET and 
                    (inactive_payment or payment == Database.NEW_PAYMENT or payment > Database.MAX_KNOWN_PAYMENT)):
                return True
            return False

        try:
            # connect and get record from database
            db_manager = DatabaseManager()
            dict_data = db_manager.get_main_record(usernum)
            record_data = {Database.KEY_FIELD[key]: value for key, value in dict_data.items() if key != Database.USERNUM}
            
            # it's country user has active country payment or inactive/new/high juridical payment with country nnet
            inactive_payment = record_data["payment"] in Database.INACTIVE_PAYMENT
            country = check_country_or_city(record_data["payment"], record_data["nnet"])
            
            # return True if it's country payment, return database manager, main data object and flag for inactive payment so not to check it later
            return country, db_manager, record_data, inactive_payment
        
        # exception while checking record
        except Exception:   
            # delete database manager and throw exception again
            del db_manager
            raise
