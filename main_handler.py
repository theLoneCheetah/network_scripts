#!/usr/bin/python3
import re
import traceback
import signal
import sys
import os
import time
from ipaddress import IPv4Address, IPv4Network, AddressValueError
# user's modules
from database_manager import DatabaseManager
from L2_manager import L2Manager
from L3_manager import L3Manager
from const import Const
from my_exception import ExceptionType, MyException


##### MAIN CLASS TO HANDLE ALL WORK #####

class MainHandler:
    def __init__(self, usernum):
        # init by usernum, declare fields for main objects
        self.__usernum = usernum
        self.__db_manager = None
        self.__switch_manager = None
        self.__record_data = {}   # user record from database
    
    # set variables for main user diagnosing
    def __diagnostics_initializer(self):
        # another main fields
        self.__switch_port = False
        self.__gateway_manager = None
        self.__correctly_filled = {}   # -1 if data from record is incorrect, 0 if empty, 1 if correct

        # flags for country, speed and unknown payment
        self.__country = False
        self.__gigabit = False
        self.__inactive_payment = False
        self.__unknown_payment = False
        
        # flags that shows how many fields are filled
        self.__ip_mask_gateway = False   # important only if __switch_port is True
        self.__direct_public_ip = False
        self.__mask_length = 0
        
        # flags for errors in diagnostics of the database record
        self.__impossible_mask = False
        self.__ip_out_of_subnet = False
        self.__incorrect_indirect_public_ip = False
        self.__different_ip_public_ip = False
        self.__incorrect_subnet = False
        self.__incorrect_switch = False
        self.__double_port = []   # there will be usernums if found doubles
        self.__double_ip = []
        
        # flags and variables for diagnostics of L2 and L3
        self.__switch_vlans = {}
        self.__have_direct_public_vlan = False
        self.__untagged_vlan_id = 0
        self.__port_vlans = {}   # VID: status
        self.__vlan_ok = False
        self.__dhcp_relay_ok = False
        self.__acl_ok = False
        self.__fiber_port = False
        self.__link_ok = False
        self.__mac_addresses = {}
        self.__mac_ok = False
        self.__port_security = False
        self.__need_to_cable_diag = False   # if necessary to cable diag later
        self.__crc_errors = 0
        self.__crc_ok = False
        self.__rx_bytes = 0
        self.__tx_bytes = 0
        self.__rx_megabit = 0
        self.__tx_megabit = 0
        self.__packets_ok = False
        self.__arp_ok = False
        
        # flags for errors in diagnostics of L2
        self.__switch_exception = None
        self.__no_vlan = False
        self.__user_vlan_instead_of_direct_public_vlan = False
        self.__direct_public_vlan_instead_of_user_vlan = False
        self.__incorrect_dhcp_relay = False
        self.__no_acl = False
        self.__wrong_acl = False
        self.__port_disabled = False
        self.__speed_settings = None
        self.__linkdown_status = None
        self.__lower_speed = None
        self.__open_cable_pairs = []
        self.__cable_diag_status = None
        self.__invalid_log_time = False
        self.__port_flapping = False
        self.__no_mac = False
        self.__many_macs = 0   # count mac addresses if there's more than 1
        
        # flags for errors in diagnostics of L3
        self.__ip_route_not_found = False
        self.__ip_interface_not_found = False
        self.__ip_interface_wrong_subnet = False
        self.__no_arp = False
        self.__arp_on_unknown_mac = ""   # here wiil be unknown mac if found
        self.__ip_incorrect_arp_on_mac = []    # here will be unknown ip addresses if found
        self.__need_to_check_mac_on_L3 = False
        self.__no_mac_on_L3 = False
    
    ##### DATABASE AND USER CARD PART #####
    
    # check payment (vznos)
    def __check_payment(self):
        # if it's country, speed is not necessary
        if self.__record_data["payment"] in Const.COUNTRY:
            self.__country = True
        # 100 Mbit if payment is known
        elif self.__record_data["payment"] in Const.FAST_ETHERNET:
            self.__gigabit = False
        # 1 Gbit if payment is known or more than limit
        elif self.__record_data["payment"] in Const.GIGABIT_ETHERNET:
            self.__gigabit = True
        # if it's new user or it has high payment for juridical, ask for speed
        elif self.__record_data["payment"] == Const.NEW_PAYMENT or self.__record_data["payment"] > Const.MAX_KNOWN_PAYMENT:
            self.__gigabit = input(f"Vznos is {self.__record_data["payment"]}. Gigabit? (y/n) ").lower() == "y"
        # user is inactive, didn't pay or disconnected
        elif self.__record_data["payment"] in Const.OLD_PAYMENT:
            self.__inactive_payment = True
        # in other cases
        else:
            self.__unknown_payment = True
        
    # check numeric record fields: port, dhcp, nserv, nnet
    def __check_number_fields(self, field, limit):
        # each field must be from 1 to some known limit
        if self.__record_data[field] == None or self.__record_data[field] == 0:
            return 0
        elif 1 <= self.__record_data[field] <= limit:
            return 1
        return -1
    
    # check ip record fields: ip, mask, gateway, switch, public_ip
    def __check_ip_fields(self, field):
        if not self.__record_data[field]:
            return 0
        try:
            IPv4Address(self.__record_data[field])
            return 1
        except AddressValueError:
            return -1
    
    # check mask and get its length
    def __calculate_mask_length(self):
        # get binary notation
        bin_mask = f"{IPv4Address(self.__record_data['mask']):b}"
        # mask should contain 1s, then 0s
        match = re.search("^(1{16,})0{2,}$", bin_mask)
        
        # if mask matches, remember its length
        if match:
            self.__mask_length = len(match.group(1))
    
    # check if ip address matches subnet
    def __check_ip_in_subnet(self):
        return IPv4Address(self.__record_data["ip"]) in IPv4Network(f"{self.__record_data['gateway']}/{self.__mask_length}", strict=False)
    
    # check if address/subnet is in local range, usually gateway, sometimes switch
    def __check_local_ip(self, address=None):
        # check only ip if it's switch or check subnet
        if address is None:
            # by default, check if mask length and gateway address are in local ranges
            if self.__mask_length not in Const.LOCAL_MASKS:
                return False
            address = self.__record_data["gateway"]
        return int(Const.FIRST_LOCAL_IP) <= int(IPv4Address(address)) <= int(Const.LAST_LOCAL_IP)
    
    # check if address/subnet is in public range, usually gateway, sometimes indirect public ip
    def __check_public_ip(self, address=None):
        # by default, check if mask and gateway define one of public subnets
        if address is None:
            address = self.__record_data["gateway"]
            return address in Const.PUBLIC_GATEWAY_MASK and self.__mask_length == Const.PUBLIC_GATEWAY_MASK[address]
        # for indirect public ip, check if it lies in public subnet
        return any(IPv4Address(address) in subnet for subnet in Const.PUBLIC_SUBNETS)
    
    # check switch ip, it can be in usual local range or in one special local subnet
    def __check_switch_ip(self):
        return self.__check_local_ip(self.__record_data["switch"]) or IPv4Address(self.__record_data["switch"]) in Const.SWITCH_OTHER_LOCAL_SUBNET
    
    # check users with the same switch and port, return list of doubles if found
    def __check_double_switch_port(self):
        usernums = self.__db_manager.get_usernum_by_switch_port(self.__record_data["switch"], self.__record_data["port"])
        return usernums if len(usernums) > 1 else []
    
    # check users with the same ip, return list of doubles if found
    def __check_double_ip(self):
        usernums = self.__db_manager.get_usernum_by_ip(self.__record_data["ip"])
        return usernums if len(usernums) > 1 else []
    
    # function to control user's database record checking
    def __check_user_card(self):
        try:
            # connect and get record from database
            self.__db_manager = DatabaseManager()
            dict_data = self.__db_manager.get_main_record(self.__usernum)
            self.__record_data = {Const.KEY_FIELD[key]: value for key, value in dict_data.items() if key != Const.USERNUM}
            
            # check payment to choose country/city and speed
            self.__check_payment()
            
            ########## TO BE WRITTEN...
            if self.__country:
                raise Exception("It's country! Help!")
            
            # check and make a note about numeric fields
            for field, limit in Const.NUMBER_FIELDS_LIMITS.items():
                self.__correctly_filled[field] = self.__check_number_fields(field, limit)
            
            # check and make a note about ip fields
            for field in Const.IP_FIELDS:
                self.__correctly_filled[field] = self.__check_ip_fields(field)
            
            # check switch ip
            if self.__correctly_filled["switch"] == 1:
                # if switch isn't correct, set a flag
                if not self.__check_switch_ip():
                    self.__incorrect_switch = True
                # if switch and port are correct, L2 diagnostics is possible
                elif self.__correctly_filled["port"] == 1:
                    self.__switch_port = True
                    # check for double port
                    self.__double_port = self.__check_double_switch_port()
            
            # check for double ip
            if self.__correctly_filled["ip"] == 1:
                self.__double_ip = self.__check_double_ip()
            
            # check mask and subnet
            if self.__correctly_filled["mask"] == 1:
                self.__calculate_mask_length()
                # set a special flag if mask's address doesn't suit to regular mask
                if not self.__mask_length:
                    self.__impossible_mask = True
                
                # if ip and gateway exist, it's possible to check subnet
                elif self.__correctly_filled["ip"] == 1 and self.__correctly_filled["gateway"] == 1:
                    # make sure ip is in the subnet, or set a flag
                    if not self.__check_ip_in_subnet():
                        self.__ip_out_of_subnet = True
                    
                    # if ip is local and has indirect public_ip, check if it's correct
                    elif self.__check_local_ip():
                        if self.__correctly_filled["public_ip"] == 1 and not self.__check_public_ip(self.__record_data["public_ip"]):
                            self.__incorrect_indirect_public_ip = True
                    
                    # if ip is public, check public_ip field is the same
                    elif self.__check_public_ip():
                        if self.__record_data["ip"] != self.__record_data["public_ip"]:
                            self.__different_ip_public_ip = True
                        else:   # if correct, check default gateway on L2 and ip route on L3
                            self.__direct_public_ip = True
                    
                    # if gateway doesn't match to known subnets
                    else:
                        self.__incorrect_subnet = True
                    
                    # if there was no errors, acl and L3 diagnostics is possible
                    if not any([self.__ip_out_of_subnet, self.__incorrect_indirect_public_ip, self.__different_ip_public_ip, self.__incorrect_subnet]):
                        self.__ip_mask_gateway = True
        
        except Exception as err:   # exception while checking record
            print("Exception while working with the database record:", traceback.print_exc(), sep="\n")
        
        finally:   # always close connection and delete database manager
            del self.__db_manager
    
    # result of database record diagnostics
    def __result_user_card(self):
        all_correct = True
        
        # if payment is unknown
        if self.__unknown_payment:
            print("Неизвестный взнос:", self.__record_data["payment"])
            all_correct = False
        # if payment is inactive
        elif self.__inactive_payment:
            print("Неактивный взнос:", self.__record_data["payment"])
            all_correct = False
        
        # print empty fields except public_ip
        if any(value == 0 for key, value in self.__correctly_filled.items() if key != "public_ip"):
            print("Не заполнены поля:", ", ".join(name for key, name in Const.KEY_OUTPUT.items() if key != "public_ip" and self.__correctly_filled[key] == 0))
            all_correct = False
        
        # print obviously incorrect fields
        if any(value == -1 for key, value in self.__correctly_filled.items()):
            print("Неверно заполнены поля:", ", ".join(name for key, name in Const.KEY_OUTPUT.items() if self.__correctly_filled[key] == -1))
            all_correct = False
        
        # double port and ip
        if self.__double_port:
            print("Дубль порт:", ", ".join(map(str, self.__double_port)))
            all_correct = False
        if self.__double_ip:
            print("Дубль айпи:", ", ".join(map(str, self.__double_ip)))
            all_correct = False
        
        # switch error separately
        if self.__incorrect_switch:
            print("Некорректный адрес свитча")
            all_correct = False
        
        # subnet errors alternatively
        if self.__impossible_mask:
            print("Неизвестная маска")
        elif self.__incorrect_subnet:
            print("Неизвестная подсеть")
        elif self.__ip_out_of_subnet:
            print("Айпи вне подсети")
        elif self.__different_ip_public_ip:
            print("Поле Внешний IP не совпадает с IP")
        elif self.__incorrect_indirect_public_ip:
            print("Некорректный внешний IP")
        # if everythin is OK and there was no errors before
        elif all_correct:
            print("OK")
    
    ##### L2 AND L3 EQUIPMENT DIAGNOSTICS PART #####
    
    # check if port in user card belongs to switch's portlist
    def __check_port_in_switch_portlist(self):
        return self.__switch_manager.check_port_in_portlist()
    
    # check port and mark flags
    def __check_port(self):
        # check port, get its type, settings and status, linkdown_status is actual if port is enabled
        self.__fiber_port, self.__port_disabled, self.__speed_settings, self.__linkdown_status, speed = self.__switch_manager.get_port_link()
        
        # if there's link
        if not self.__port_disabled and not self.__linkdown_status:
            # check if speed is satisfying, cable diag needed if not
            if not (speed == Const.NORMAL_SPEED[True] or not self.__gigabit and speed == Const.NORMAL_SPEED[False]):
                self.__need_to_cable_diag = True
                self.__lower_speed = speed
            # otherwise it's ok
            else: 
                self.__link_ok = True
    
    # perform cable diagnostics
    def __try_cable_diag(self):
        # can't perform is its fiber (SFP) port
        if self.__fiber_port:
            return
        
        # result can be different pairs or just status
        res = self.__switch_manager.cable_diag()
        
        # if result is list, it marks opened pairs
        if isinstance(res, list):
            self.__open_cable_pairs = res
        # if result is string, it's just status
        else:
            self.__cable_diag_status = res
    
    # check if port is flapping
    def __check_log(self):
        # get flapping count and last flap remoteness in time
        try:
            count_flapping, last_flap_remoteness = self.__switch_manager.get_log_port_flapping()
        except ValueError:
            self.__invalid_log_time = True
            return
        
        # if flapping is too often, mark flag and try cable diag afterall
        if last_flap_remoteness < Const.LAST_FLAP_MAX_MINUTE_REMOTENESS and count_flapping >= Const.MIN_COUNT_FLAPPING:
            self.__port_flapping = True
            self.__need_to_cable_diag = True
    
    # check mac addresses and get as a set
    def __check_mac(self):
        # get set of all mac addresses
        self.__mac_addresses = self.__switch_manager.get_mac_addresses_port()
        
        # error when there's no mac, cable diag needed
        if not self.__mac_addresses:
            self.__no_mac = True
            self.__need_to_cable_diag = True
        # error when there're more than 1 mac
        elif len(self.__mac_addresses) > 1:
            self.__many_macs = len(self.__mac_addresses)
        # correct flag if only 1 mac
        else:
            self.__mac_ok = True
        
        # check if port security is enabled
        self.__port_security = self.__switch_manager.get_port_security()
    
    # check crc errors
    def __check_crc(self):
        # get numbers of rx crc errors, will be zero if OK
        self.__crc_errors = self.__switch_manager.get_crc_errors_port()
        
        # flag if crc ok
        if self.__crc_errors == 0:
            self.__crc_ok = True
    
    # calculate megabit from bytes, bytes number may be in the period of 1 or 5 seconds
    def _byte_to_megabit(bytes_count):
        return round(bytes_count * 8 / 1024 / 1024)
    
    # check packet bytes and calculate megabit
    def __check_packets(self):
        # get rx and tx bytes
        self.__rx_bytes, self.__tx_bytes = self.__switch_manager.get_packets_port()
        
        # calculate to megabit
        self.__rx_megabit = MainHandler._byte_to_megabit(self.__rx_bytes)
        self.__tx_megabit = MainHandler._byte_to_megabit(self.__tx_bytes)
        
        # set flag that packets successfully checked
        self.__packets_ok = True
    
    # check dhcp relay settings for user's vlan
    def __check_dhcp_relay(self):
        def check_servers_dhcp_relay(dhcp_servers):
            return dhcp_servers and dhcp_servers[0] == Const.PRIMARY_DHCP_SERVER and dhcp_servers[1] in Const.SECONDARY_DHCP_SERVERS
        
        def check_vlan_id_dhcp_relay(untagged_vlan_id, vlan_ids_list):
            return any([i != "" and untagged_vlan_id in range(int(i.split("-")[0]), int(i.split("-")[-1]) + 1) for i in vlan_ids_list])
        
        # get servers and vlan ids
        dhcp_servers, vlan_ids = self.__switch_manager.get_dhcp_relay()

        # vlan_ids = -1 means switch doesn't have to have dhcp relay
        if vlan_ids == -1:
            # decide only basing on servers
            if check_servers_dhcp_relay(dhcp_servers):
                self.__dhcp_relay_ok = True
            else:
                self.__incorrect_dhcp_relay = True
        # for switches with dchp relay, ok if dhcp servers are correct and vlan id is enabled in dhcp relay
        elif check_servers_dhcp_relay(dhcp_servers) and check_vlan_id_dhcp_relay(self.__untagged_vlan_id, vlan_ids):
            self.__dhcp_relay_ok = True
        # incorrect otherwise
        else:
            self.__incorrect_dhcp_relay = True

    # check vlans on switch and on port
    def __check_vlan(self):
        # get switch vlans
        self.__switch_vlans = self.__switch_manager.get_switch_vlans()
        self.__have_direct_public_vlan = Const.DIRECT_PUBLIC_VLAN in self.__switch_vlans
        
        # get port vlans
        self.__port_vlans = self.__switch_manager.get_port_vlans()
        
        # no_vlan flag if port has no vlans of any status
        if not self.__port_vlans:
            self.__no_vlan = True
        
        # check if there's only 1 untagged vlan, remember it
        elif Const.VLAN_STATUSES[0] in self.__port_vlans and len(self.__port_vlans[Const.VLAN_STATUSES[0]]) == 1:
            self.__untagged_vlan_id = self.__port_vlans[Const.VLAN_STATUSES[0]][0]
            
            # mark flag if port doesn't have direct_public_vlan when it's on switch
            if self.__direct_public_ip and self.__have_direct_public_vlan and self.__untagged_vlan_id != Const.DIRECT_PUBLIC_VLAN:
                self.__user_vlan_instead_of_direct_public_vlan = True
            # mark flag if port doesn't have user vlan
            elif not self.__direct_public_ip and self.__untagged_vlan_id == Const.DIRECT_PUBLIC_VLAN:
                self.__direct_public_vlan_instead_of_user_vlan = True
            # correct flag if port has only 1 vlan in untagged
            elif len(self.__port_vlans.keys()) == 1:
                self.__vlan_ok = True
            
            # when there's 1 untagged vlan on port, check dhcp relay
            self.__check_dhcp_relay()
    
    # transform acl entry to ip, entry should has 8 hex symbols
    def __get_ip_from_acl(self, acl_entry):
        return ".".join([str(int(acl_entry[2*i : 2*i+2], 16)) for i in range(4)])
    
    # check access profile options on port
    def __check_acl(self):
        # get acl entries on port in hex notation
        hex_entries = self.__switch_manager.get_port_acl()
        
        # if there's less than needed entries
        if len(hex_entries) < 2:
            self.__no_acl = True
        # if at least one entry doesn't match ip
        elif any([self.__get_ip_from_acl(i) != self.__record_data["ip"] for i in hex_entries]):
            self.__wrong_acl = True
        # if everything is ok
        else:
            self.__acl_ok = True

    # check for direct public ip and find its gateway where arp should be
    def __find_actual_gateway(self):
        # init L3 manager by user record's gateway if ip is local
        if not self.__direct_public_ip:
            self.__gateway_manager = L3Manager(self.__record_data["gateway"], self.__record_data["ip"])
            return
        
        # on Lensoveta 23, define gateway address for direct public ip
        if self.__record_data["street"] == Const.LENSOVETA_ADDRESS_GATEWAY["street"] and self.__record_data["house"] == Const.LENSOVETA_ADDRESS_GATEWAY["house"]:
            self.__gateway_manager = L3Manager(Const.LENSOVETA_ADDRESS_GATEWAY["gateway"], self.__record_data["ip"])
            return
        
        # otherwise, find default gateway address on switch
        gateway = self.__switch_manager.get_default_gateway()
        
        # may need from 1 to 3 iterations
        while True:
            # create or update L3 manager and find ip route for direct public ip
            self.__gateway_manager = L3Manager(gateway, self.__record_data["ip"])
            gateway = self.__gateway_manager.check_ip_route()

            # if nothing found, mark flag and keep current L3 manager
            if not gateway:
                self.__ip_route_not_found = True
                return
            
            # break if self-route found
            elif gateway == self.__record_data["ip"]:
                return
            
            # delete previous and continue with new L3 manager if new next hop found
            del self.__gateway_manager
    
    # compare subnet from L3 ip interface with subnet from user card
    def __check_vlan_subnet(self):
        # can't diagnose if don't have exact untagged vlan
        if not self.__untagged_vlan_id:
            return
        
        # L3 manager checks ipif by vlan and compares with user's subnet, ipif name for direct public ip can be last 2 octets of gateway
        res = self.__gateway_manager.check_ip_interface_subnet((self.__untagged_vlan_id, self.__switch_vlans[self.__untagged_vlan_id]), self.__record_data["gateway"],
                                                                self.__mask_length, self.__record_data["gateway"][-7:] if self.__direct_public_ip else None)
        
        # rarely when ipif doesn't exist or has another name
        if res == -1:
            self.__ip_interface_not_found = True
        # if ipif's by vlan subnet differs from user's subnet
        elif not res:
            self.__ip_interface_wrong_subnet = True
    
    # try to check arp on mac if there's only 1 mac
    def __get_ips_from_arpentry_mac(self):
        # if there's no mac or more than 1, can't find
        if len(self.__mac_addresses) != 1:
            return []
        
        # return list of ip addresses with arp on this mac
        return self.__gateway_manager.check_arpentry_mac_return_ips(*self.__mac_addresses)
    
    # check mac visibility on L3 and set a flag if not visible
    def __check_mac_visible_on_L3(self):
        # if there's no mac or more than 1, can't find
        if len(self.__mac_addresses) != 1:
            return
        
        # flag to simplify output control, when mac on L3 info should be displayed
        self.__need_to_check_mac_on_L3 = True
        
        # set flag True if no mac found
        self.__no_mac_on_L3 = self.__gateway_manager.check_mac_on_L3(*self.__mac_addresses)
    
    # check arpentry by ip and mac and try other options on L3
    def __check_arpentry_by_ip(self):
        # get mac from arp found by ip
        mac = self.__gateway_manager.check_arpentry_ip_return_mac()
        
        # get ip addresses from arp found by mac
        ips = self.__get_ips_from_arpentry_mac()
        
        # found arp by ip and its mac is known
        if mac and mac in self.__mac_addresses:
            # mark flag that arp is correct
            self.__arp_ok = True
            
            # if found many arps by mac, remember extra ip addresses
            if len(ips) > 1:
                self.__ip_incorrect_arp_on_mac = [ip for ip in ips if ip != self.__record_data["ip"]]
        
        # if no arp found or arp has unknown mac
        else:
            # record extra ip addresses from arps by mac if have any
            self.__ip_incorrect_arp_on_mac = ips
            
            # if arp by ip exists on unknown mac, remember it
            if mac and mac not in self.__mac_addresses:
                self.__arp_on_unknown_mac = mac
            
            # mark flag if no arp found at all
            self.__no_arp = not self.__ip_incorrect_arp_on_mac and not self.__arp_on_unknown_mac
            
            # if no arp on mac found, check mac reaches L3
            if not self.__ip_incorrect_arp_on_mac:
                self.__check_mac_visible_on_L3()
    
    # function to control diagnosing L2 and L3
    def __check_L2_L3(self):
        try:
            if not self.__switch_port:   # exception if there's no data
                raise MyException(ExceptionType.NO_SWITCH_PORT)
            
            # connect to switch only if switch and port are known
            self.__switch_manager = L2Manager(self.__record_data["switch"], self.__record_data["port"])
            
            # exception and flag if port is outside switch's portlist
            if not self.__check_port_in_switch_portlist():
                raise MyException(ExceptionType.PORT_OUTSIDE_OF_PORTLIST)
            
            # if subnet is correct, check vlan and acl
            if self.__ip_mask_gateway:
                # check vlan
                self.__check_vlan()
                
                # check acl
                self.__check_acl()
            
            # check port
            self.__check_port()
                
            # check crc errors in any case
            self.__check_crc()
            
            # if link is down not because of disabled port, try cable diag
            if self.__linkdown_status:
                self.__try_cable_diag()
            # in other case, if port is enabled, diagnose further options
            elif not self.__port_disabled:
                # check log for flapping
                self.__check_log()
                
                # check mac
                self.__check_mac()
                
                # check packets
                self.__check_packets()
                
                # if speed isn't relevant, port is flapping or there's no mac, try cable_diag afterall
                if self.__need_to_cable_diag:
                    self.__try_cable_diag()
            
            # if subnet isn't correct, quit and send a message
            if not self.__ip_mask_gateway:
                raise MyException(ExceptionType.NO_SUBNET)
            
            # create L3 manager and check arpentry
            self.__find_actual_gateway()
            self.__check_vlan_subnet()
            self.__check_arpentry_by_ip()
        # user's exception include special text for output
        except MyException as err:
            # save exception's text if it's not subnet error, it's switch error
            if self.__ip_mask_gateway:
                self.__switch_exception = err
        # exceptions while working with L2 or L3, show traceback
        except Exception:
            print("Exception while working with equipment:", traceback.print_exc(), sep="\n")
        # always close connection and delete L2 and L3 managers
        finally:
            if self.__switch_manager:
                del self.__switch_manager
            if self.__gateway_manager:
                del self.__gateway_manager
        
        """# user's exception include special text for output
        except MyException as err:
            # save exception's text if it's not subnet error, it's switch error
            if self.__ip_mask_gateway:
                self.__switch_exception = err
        # exceptions while working with L2 or L3, show traceback
        except Exception:
            print("Exception while working with equipment:", traceback.print_exc(), sep="\n")"""
    
    # result of L2 and L3 diagnostics
    def __result_L2_L3(self):
        # terminate when any fatal error discovered
        if self.__switch_exception:
            print(self.__switch_exception)
            return

        # port: if it is fiber or has settings
        if self.__fiber_port:
            print("Оптический порт")
        if self.__speed_settings:
            print("Скорость ограничена вручную в", self.__speed_settings)
        # port: status and speed
        if self.__port_disabled:
            print("Порт выключен")
        elif self.__linkdown_status:
            print("Состояние порта:", self.__linkdown_status)
        elif self.__lower_speed and not self.__speed_settings:
            print("Линк", self.__lower_speed, "вместо", Const.NORMAL_SPEED[self.__gigabit])
        elif self.__link_ok:
            print("Линк OK")
        
        # if port is or was flapping
        if self.__invalid_log_time:
            print("Сбились настройки времени на L2")
        elif self.__port_flapping:
            print("Линк скачет")
        
        # crc errors: count, no crc
        if self.__crc_errors:
            print("Ошибки CRC:", self.__crc_errors)
        elif self.__crc_ok:
            print("Ошибки CRC: OK")
        
        # if linkup, show mac and packets
        if not self.__linkdown_status:
            # mac address: no mac, many macs
            if self.__no_mac:
                print("Нет мака на порту")
            elif self.__many_macs:
                print("Маков на порту:", self.__many_macs)
            elif self.__mac_ok:
                print("Мак OK")
            
            # port security if enabled, makes sense when linkup
            if self.__port_security:
                print("Включён port_security")
            
            # packets: rx and tx bytes and megabit
            if self.__packets_ok:
                print(f"RX: {self.__rx_bytes} bytes ({self.__rx_megabit} Mbit), TX: {self.__tx_bytes} bytes ({self.__tx_megabit} Mbit)")
        
        # cable diag: just status or a list of open pairs
        if self.__cable_diag_status:
            print("Кабдиаг", self.__cable_diag_status)
        elif self.__open_cable_pairs:
            # list has records as [pair, status, meter]
            print("Кабдиаг", ", ".join(map(lambda x: f"{x[0]}п {x[2]}м {x[1].upper()}" if len(x) == 3 and all(x) else f"{x[0]}п {x[1].upper()}", self.__open_cable_pairs)))
        
        # if there's no correct subnet, end output
        if not self.__ip_mask_gateway:
            return
        
        # vlan: no vlan, wrong tags, wrong untagged vlan, ok
        if self.__no_vlan:
            print("Нет влана на порту")
        for ind, status in enumerate(Const.VLAN_STATUSES):
            if status in self.__port_vlans and (ind != 0 or not self.__untagged_vlan_id):
                print("Влан", ", ".join(map(str, self.__port_vlans[status])), "в", status)
        if self.__untagged_vlan_id:
            if self.__user_vlan_instead_of_direct_public_vlan:
                print(f"Назначен юзерский влан вместо {Const.DIRECT_PUBLIC_VLAN}")
            elif self.__direct_public_vlan_instead_of_user_vlan:
                print(f"Назначен влан {Const.DIRECT_PUBLIC_VLAN} вместо юзерского")
            elif self.__vlan_ok:
                print("Влан OK")
        
        # dhcp relay: incorrect, ok
        if self.__incorrect_dhcp_relay:
            print("Не настроен DHCP relay")
        elif self.__dhcp_relay_ok:
            print("DHCP relay OK")
        
        # acl: no/less than needed, wrong entries, ok
        if self.__no_acl:
            print("Отсутствует правило ACL")
        elif self.__wrong_acl:
            print("ACL не соответствует IP")
        elif self.__acl_ok:
            print("ACL OK")
        
        # ip route: if not found
        if self.__ip_route_not_found:
            print("Не найден маршрут для прямого внешнего IP на L3")
        
        # arp: no arp, arp on unknown mac, correct
        if self.__no_arp:
            print("ARP не найдена")
        elif self.__arp_on_unknown_mac:
            print("ARP найдена на неизвестный мак:", self.__arp_on_unknown_mac)
        elif self.__arp_ok:
            print("ARP OK")
        # if found arp by mac with wrong ip addresses, is possible even if arp ok or unknown mac
        if self.__ip_incorrect_arp_on_mac:
            print("По маку на порту найдена неверная ARP:", ", ".join(self.__ip_incorrect_arp_on_mac))
        # if mac was checked, print found or not
        if self.__need_to_check_mac_on_L3:
            if self.__no_mac_on_L3:
                print("Мак не виден на L3")
            else:
                print("Мак виден на L3")
        
        # ip interface on L3: if not found or subnet for vlan is wrong
        if self.__ip_interface_not_found:
            print("Не найден интерфейс для юзерского влана")
        elif self.__ip_interface_wrong_subnet:
            print("Подсеть интерфейса для юзерского влана не соответствует подсети из карточки")
    
    # main function
    def check_all(self):
        # start init
        self.__diagnostics_initializer()

        # check all functions
        self.__check_user_card()
        self.__check_L2_L3()
        
        # print user card part
        print("-" * 20)
        print("ДИАГНОСТИКА КАРТОЧКИ:")
        self.__result_user_card()
        
        # print L2 and L3 diagnostics part
        print("-" * 20)
        print("ДИАГНОСТИКА ОБОРУДОВАНИЯ:")
        self.__result_L2_L3()
    
    # print all necessary fields
    def print_record(self):
        print("-" * 20)
        
        # print usernum and other fields
        print(f"{Const.USERNUM.name}:{' '*(12-len(Const.USERNUM.name))}{self.__usernum}")
        for key in self.__record_data:
            print(f"{key}:{' '*(12-len(key))}{self.__record_data[key]}")
        
        print("-" * 20)
    
    ##### PACKET SCANNING #####

    # handler for safe exiting, gets signal number and stack frame and exits successfully
    def __handle_exit(self, sig, frame):
        sys.exit(0)

    # start init
    def __packet_scan_initializer(self):
        # handle signal with "kill" command and CTRL+C key for safe exiting
        signal.signal(signal.SIGTERM, self.__handle_exit)
        signal.signal(signal.SIGINT, self.__handle_exit)

        # create pipe if not exists
        if not os.path.exists(Const.PIPE):
            os.mkfifo(Const.PIPE)

        # variables
        self.__rx_megabit = 0
        self.__max_rx_megabit = 0
        self.__tx_megabit = 0
        self.__max_tx_megabit = 0

    # working with database
    def __get_switch_port(self):
        try:
            # connect and get user's switch and port from database
            self.__db_manager = DatabaseManager()
            dict_data = self.__db_manager.get_switch_port(self.__usernum)
            self.__record_data = {Const.KEY_FIELD[key]: value for key, value in dict_data.items()}
        
        finally:   # always close connection and delete database manager
            del self.__db_manager
    
    # check and write packet to named pipe
    def __scan_packet(self):
        # calculate megabit and max megabit
        def calculate_current_and_max(rx_bytes, tx_bytes):
            self.__rx_megabit = MainHandler._byte_to_megabit(rx_bytes)
            self.__tx_megabit = MainHandler._byte_to_megabit(tx_bytes)
            self.__max_rx_megabit = max(self.__max_rx_megabit, self.__rx_megabit)
            self.__max_tx_megabit = max(self.__max_tx_megabit, self.__tx_megabit)

        try:
            # connect to switch
            self.__switch_manager = L2Manager(self.__record_data["switch"], self.__record_data["port"])
            
            # open pipe with buffering by every line, not to collect lines in python script's buffer
            with open(Const.PIPE, "w", buffering=1) as pipe:
                # run until interrupted
                while True:
                    # get bytes and calculate megabit with max
                    calculate_current_and_max(*self.__switch_manager.get_packets_port())

                    # try block needed because bash script always reads data from pipe and closes promtply
                    try:
                        # write rx, rx_max, tx, tx_max with spaces in one string into pipe
                        pipe.write(f"{self.__rx_megabit} {self.__max_rx_megabit} {self.__tx_megabit} {self.__max_tx_megabit}\n")

                        # forcely write data from buffer into pipe
                        pipe.flush()
                    
                    # ignore broken pipe error when bash is not reading
                    except BrokenPipeError:
                        pass
        
        # catch error for correct exiting: eof ending, broken pipe by bash, exit from bash
        except (EOFError, BrokenPipeError, SystemExit):
            pass
            
        # always close connection and delete L2 and L3 managers
        finally:
            if self.__switch_manager:
                del self.__switch_manager

    def check_packet(self):
        # start init
        self.__packet_scan_initializer()

        # get data from database for switch connection
        try:
            self.__get_switch_port()
        except Exception as err:   # exception while checking record
            print("Exception while working with the database record:", traceback.print_exc(), sep="\n")

        # scan packet on switch and provide data for bash script by pipe
        try:
            self.__scan_packet()
        # exceptions while working with L2, show traceback
        except Exception as err:
            print("Exception while working with equipment:", traceback.print_exc(), sep="\n")