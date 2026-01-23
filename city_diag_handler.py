#!/usr/bin/python3
from __future__ import annotations
from typing import TYPE_CHECKING, Any, override
import re
import traceback
from ipaddress import IPv4Address, IPv4Network
# user's modules
from diag_handler import DiagHandler
from L2_manager import L2Manager
from L3_manager import L3Manager
from const import Database, Provider, CitySwitch
from my_exception import ExceptionType, MyException

# import as type only by Pylance (for VS Code)
if TYPE_CHECKING:
    from database_manager import DatabaseManager


##### MAIN CLASS TO HANDLE CITY USER DIAGNOSTICS #####

class CityDiagHandler(DiagHandler):
    # annotations of inherited attributes
    _switch_manager: L2Manager | None
    _gateway_manager: L3Manager | None
    # class attributes annotations
    __print_output: bool
    __gigabit: bool
    __switch_port: bool
    __ip_mask_gateway: bool
    __direct_public_ip: bool
    __mask_length: int
    __unknown_payment: bool
    __impossible_mask: bool
    __ip_out_of_subnet: bool
    __incorrect_indirect_public_ip: bool
    __incorrect_subnet: bool
    __incorrect_switch: bool
    __double_port: list[int]
    __switch_exception: MyException | None
    __switch_vlans: dict[int, str]
    __have_direct_public_vlan: bool
    __untagged_vlan_id: int
    __port_vlans: dict[str, list[int]]
    __vlan_ok: bool
    __no_vlan: bool
    __user_vlan_instead_of_direct_public_vlan: bool
    __direct_public_vlan_instead_of_user_vlan: bool
    __dhcp_relay_ok: bool
    __incorrect_dhcp_relay: bool
    __acl_ok: bool
    __no_acl: bool
    __wrong_acl: bool
    __fiber_port: bool
    __link_ok: bool
    __port_disabled: bool
    __speed_settings: str
    __linkdown_status: str
    __lower_speed: str
    __need_to_cable_diag: bool
    __open_cable_pairs: list[tuple[int, str] | tuple[int, str, int]]
    __cable_diag_status: str
    __invalid_log_time: bool
    __port_flapping: bool
    __port_security: bool
    __crc_errors: int
    __crc_ok: bool
    __rx_bytes: int
    __tx_bytes: int
    __rx_megabit: int
    __tx_megabit: int
    __packets_ok: bool
    __ip_route_not_found: bool

    def __init__(self, usernum: int, db_manager: DatabaseManager, record_data: dict[str, Any], inactive_payment: bool, print_output: bool = False) -> None:
        # init with base constructor
        super().__init__(usernum, db_manager, record_data, inactive_payment)

        # L2 and L3 managers
        self._switch_manager: L2Manager | None = None
        self._gateway_manager: L3Manager | None = None

        # indicate if terminal output needed
        self.__print_output = print_output


        # attributes for diagnostics of the database record

        # -1 if data from record is incorrect, 0 if empty, 1 if correct
        self._correctly_filled = {}

        # set variables for main user diagnosing
        
        self.__gigabit = False
        self.__switch_port = False   # if has correct switch and port
        self.__ip_mask_gateway = False   # important only if __switch_port is True
        self.__direct_public_ip = False
        self.__mask_length = 0
        
        # flags for errors in diagnostics of the database record
        self.__unknown_payment = False
        self.__impossible_mask = False
        self.__ip_out_of_subnet = False
        self.__incorrect_indirect_public_ip = False
        self.__incorrect_subnet = False
        self.__incorrect_switch = False
        self.__double_port = []   # there will be usernums if found doubles
        

        # attributes for diagnostics of L2 and L3
        
        # user's exception while working and switch
        self.__switch_exception = None

        # vlan
        self.__switch_vlans = {}
        self.__have_direct_public_vlan = False
        self.__untagged_vlan_id = 0
        self.__port_vlans = {}   # status: list of VIDs
        self.__vlan_ok = False
        self.__no_vlan = False
        self.__user_vlan_instead_of_direct_public_vlan = False
        self.__direct_public_vlan_instead_of_user_vlan = False
        
        # dhcp relay
        self.__dhcp_relay_ok = False
        self.__incorrect_dhcp_relay = False

        # acl
        self.__acl_ok = False
        self.__no_acl = False
        self.__wrong_acl = False

        # port
        self.__fiber_port = False
        self.__link_ok = False
        self.__port_disabled = False
        self.__speed_settings = ""
        self.__linkdown_status = ""
        self.__lower_speed = ""

        # cable diagnostics
        self.__need_to_cable_diag = False   # if necessary to cable diag later
        self.__open_cable_pairs = []   # list of pairs: number, state, meter optionally
        self.__cable_diag_status = ""

        # log, port flapping
        self.__invalid_log_time = False
        self.__port_flapping = False
        
        # port security
        self.__port_security = False
        
        # crc errors
        self.__crc_errors = 0
        self.__crc_ok = False

        # packets
        self.__rx_bytes = 0
        self.__tx_bytes = 0
        self.__rx_megabit = 0
        self.__tx_megabit = 0
        self.__packets_ok = False
        
        # ip route on L3
        self.__ip_route_not_found = False
    

    ##### DATABASE AND USER CARD PART #####
    
    @override
    # function to control user's database record checking
    def _check_user_card(self) -> None:
        try:
            # check payment field
            self.__check_payment()

            # check and make a note about numeric fields
            for field, limit in Provider.NUMBER_FIELDS_LIMITS.items():
                self._correctly_filled[field] = self.__check_number_fields(field, limit)
            
            # check and make a note about ip fields
            for field in Provider.IP_FIELDS:
                self._correctly_filled[field] = self._check_ip_fields(field)
            
            # check switch ip
            if self._correctly_filled["switch"] == 1:
                # if switch isn't correct, set a flag
                if not self.__check_switch_ip():
                    self.__incorrect_switch = True
                # if switch and port are correct, L2 diagnostics is possible
                elif self._correctly_filled["port"] == 1:
                    self.__switch_port = True
                    # check for double port
                    self.__check_double_switch_port()
            
            # check for double ip
            if self._correctly_filled["ip"] == 1:
                self._check_double_ip()
            
            # check mask and subnet
            if self._correctly_filled["mask"] == 1:
                self.__calculate_mask_length()
                # set a special flag if mask's address doesn't suit to regular mask
                if not self.__mask_length:
                    self.__impossible_mask = True
                
                # if ip and gateway exist, it's possible to check subnet
                elif self._correctly_filled["ip"] == 1 and self._correctly_filled["gateway"] == 1:
                    # make sure ip is in the subnet, or set a flag
                    if not self.__check_ip_in_subnet():
                        self.__ip_out_of_subnet = True
                    
                    # if ip is local and has indirect public_ip, check if it's correct
                    elif self.__check_local_ip():
                        if self._correctly_filled["public_ip"] == 1 and not self.__check_public_ip(self._record_data["public_ip"]):
                            self.__incorrect_indirect_public_ip = True
                    
                    # if ip is public, check public_ip field is the same
                    elif self.__check_public_ip():
                        if self._record_data["ip"] != self._record_data["public_ip"]:
                            self._different_ip_public_ip = True
                        else:   # if correct, check default gateway on L2 and ip route on L3
                            self.__direct_public_ip = True
                    
                    # if gateway doesn't match to known subnets
                    else:
                        self.__incorrect_subnet = True
                    
                    # if there was no errors, acl and L3 diagnostics is possible
                    if not any([self.__ip_out_of_subnet, self.__incorrect_indirect_public_ip, self._different_ip_public_ip, self.__incorrect_subnet]):
                        self.__ip_mask_gateway = True
        
        except Exception:   # exception while checking record
            print("Exception while working with the database record:")
            traceback.print_exc()
        
        finally:   # always close connection and delete database manager
            del self._db_manager
    
    # check payment (vznos)
    def __check_payment(self) -> None:
        # 100 Mbit if payment is known
        if self._record_data["payment"] in Database.FAST_ETHERNET:
            self.__gigabit = False
        # 1 Gbit if payment is known or more than limit
        elif self._record_data["payment"] in Database.GIGABIT_ETHERNET:
            self.__gigabit = True
        # if it's new user or it has high payment for juridical, ask for speed
        elif self._record_data["payment"] == Database.NEW_PAYMENT or self._record_data["payment"] > Database.MAX_KNOWN_PAYMENT:
            self.__gigabit = input(f"Vznos is {self._record_data["payment"]}. Gigabit? (y/n) ").lower() == "y"
        # in other cases, if it's not old payment
        elif not self._inactive_payment:
            self.__unknown_payment = True

    # check numeric record fields: port, dhcp, nserv, nnet
    def __check_number_fields(self, field: str, limit: int) -> int:
        # each field must be from 1 to some known limit
        if self._record_data[field] == None or self._record_data[field] == 0:
            return 0
        elif 1 <= self._record_data[field] <= limit:
            return 1
        return -1
    
    # check users with the same switch and port, return list of doubles if found
    def __check_double_switch_port(self) -> None:
        usernums = self._db_manager.get_usernum_by_switch_port(self._record_data["switch"], self._record_data["port"])
        self.__double_port = usernums if len(usernums) > 1 else []
    
    # check mask and get its length
    def __calculate_mask_length(self) -> None:
        # get binary notation
        bin_mask = f"{IPv4Address(self._record_data['mask']):b}"
        # mask should contain 1s, then 0s
        match = re.search("^(1{16,})0{2,}$", bin_mask)
        
        # if mask matches, remember its length
        if match:
            self.__mask_length = len(match.group(1))
    
    # check if ip address matches subnet
    def __check_ip_in_subnet(self) -> bool:
        return IPv4Address(self._record_data["ip"]) in IPv4Network(f"{self._record_data['gateway']}/{self.__mask_length}", strict=False)

    # check switch ip, it can be in usual local range or in one special local subnet
    def __check_switch_ip(self) -> bool:
        return self.__check_local_ip(self._record_data["switch"]) or IPv4Address(self._record_data["switch"]) in Provider.SWITCH_OTHER_LOCAL_SUBNET
    
    # check if address/subnet is in local range, usually gateway, sometimes switch
    def __check_local_ip(self, address: str | None = None) -> bool:
        # check only ip if it's switch or check subnet
        if address is None:
            # by default, check if mask length and gateway address are in local ranges
            if self.__mask_length not in Provider.LOCAL_MASKS:
                return False
            address = self._record_data["gateway"]
        return int(Provider.FIRST_LOCAL_IP) <= int(IPv4Address(address)) <= int(Provider.LAST_LOCAL_IP)
    
    # check if address/subnet is in public range, usually gateway, sometimes indirect public ip
    def __check_public_ip(self, address: str | None = None) -> bool:
        # by default, check if mask and gateway define one of public subnets
        if address is None:
            address = self._record_data["gateway"]
            return address in Provider.PUBLIC_GATEWAY_MASK and self.__mask_length == Provider.PUBLIC_GATEWAY_MASK[address]
        # for indirect public ip, check if it lies in public subnet
        return any(IPv4Address(address) in subnet for subnet in Provider.PUBLIC_SUBNETS)
    
    # result of database record diagnostics
    @override
    def _result_user_card(self) -> None:
        # flag to monitor if all diagnostics are ok
        all_correct = True
        
        # if payment is unknown
        if self.__unknown_payment:
            print("Неизвестный взнос:", self._record_data["payment"])
            all_correct = False
        # if payment is inactive
        elif self._inactive_payment:
            print("Неактивный взнос:", self._record_data["payment"])
            all_correct = False
        
        # print empty fields except public_ip
        if any(value == 0 for key, value in self._correctly_filled.items() if key != "public_ip"):
            print("Не заполнены поля:", ", ".join(name for key, name in Database.KEY_OUTPUT.items() if key != "public_ip" and self._correctly_filled[key] == 0))
            all_correct = False
        
        # print obviously incorrect fields
        if any(value == -1 for key, value in self._correctly_filled.items()):
            print("Неверно заполнены поля:", ", ".join(name for key, name in Database.KEY_OUTPUT.items() if self._correctly_filled[key] == -1))
            all_correct = False
        
        # double port and ip
        if self.__double_port:
            print("Дубль порт:", ", ".join(map(str, self.__double_port)))
            all_correct = False
        if self._double_ip:
            print("Дубль айпи:", ", ".join(map(str, self._double_ip)))
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
        elif self._different_ip_public_ip:
            print("Поле Внешний IP не совпадает с IP")
        elif self.__incorrect_indirect_public_ip:
            print("Некорректный внешний IP")
        # if everythin is OK and there was no errors before
        elif all_correct:
            print("OK")
    
    
    ##### L2 AND L3 EQUIPMENT DIAGNOSTICS PART #####

    # function to control diagnosing L2 and L3
    @override
    def _check_L2_L3(self) -> None:
        try:
            if not self.__switch_port:   # exception if there's no data
                raise MyException(ExceptionType.NO_SWITCH_PORT)
            
            # connect to switch only if switch and port are known
            self._switch_manager = L2Manager(self._record_data["switch"], self._record_data["port"], self.__print_output)
            
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
                self._check_mac()
                
                # check packets
                self.__check_packets()
                
                # if speed isn't relevant, port is flapping or there's no mac, try cable_diag afterall
                if self.__need_to_cable_diag:
                    self.__try_cable_diag()
            
            # if subnet isn't correct, quit and send a message
            if not self.__ip_mask_gateway:
                raise MyException(ExceptionType.NO_SUBNET)
            
            # create L3 manager
            self._find_actual_gateway()

            # check ip interface
            self._check_vlan_subnet()

            # check arpentry
            self._check_arpentry_by_ip()
       
        # user's exception include special text for output
        except MyException as err:
            # save exception's text if it's not subnet error, it's switch error
            if self.__ip_mask_gateway:
                self.__switch_exception = err
        # exceptions while working with L2 or L3, show traceback
        except Exception:
            print("Exception while working with equipment:")
            traceback.print_exc()
        
        # always close connection and delete L2 and L3 managers
        finally:
            if self._switch_manager:
                del self._switch_manager
            if self._gateway_manager:
                del self._gateway_manager
        
        """ # user's exception include special text for output
        except MyException as err:
            # save exception's text if it's not subnet error, it's switch error
            if self.__ip_mask_gateway:
                self.__switch_exception = err
        # exceptions while working with L2 or L3, show traceback
        except Exception:
            print("Exception while working with equipment:")
            traceback.print_exc()"""
    
    # check if port in user card belongs to switch's portlist
    def __check_port_in_switch_portlist(self) -> bool:
        return self._switch_manager.check_port_in_portlist()
    
    # check vlans on switch and on port
    def __check_vlan(self) -> None:
        # get switch vlans
        self.__switch_vlans = self._switch_manager.get_switch_vlans()
        self.__have_direct_public_vlan = Provider.DIRECT_PUBLIC_VLAN in self.__switch_vlans
        
        # get port vlans
        self.__port_vlans = self._switch_manager.get_port_vlans()
        
        # no_vlan flag if port has no vlans of any status
        if not self.__port_vlans:
            self.__no_vlan = True
        
        # check if there's only 1 untagged vlan, remember it
        elif CitySwitch.VLAN_STATUSES[0] in self.__port_vlans and len(self.__port_vlans[CitySwitch.VLAN_STATUSES[0]]) == 1:
            self.__untagged_vlan_id = self.__port_vlans[CitySwitch.VLAN_STATUSES[0]][0]
            
            # mark flag if port doesn't have direct_public_vlan when it's on switch
            if self.__direct_public_ip and self.__have_direct_public_vlan and self.__untagged_vlan_id != Provider.DIRECT_PUBLIC_VLAN:
                self.__user_vlan_instead_of_direct_public_vlan = True
            # mark flag if port doesn't have user vlan
            elif not self.__direct_public_ip and self.__untagged_vlan_id == Provider.DIRECT_PUBLIC_VLAN:
                self.__direct_public_vlan_instead_of_user_vlan = True
            # correct flag if port has only 1 vlan in untagged
            elif len(self.__port_vlans.keys()) == 1:
                self.__vlan_ok = True
            
            # when there's 1 untagged vlan on port, check dhcp relay
            self.__check_dhcp_relay()
    
    # check dhcp relay settings for user's vlan
    def __check_dhcp_relay(self) -> None:
        def check_servers_dhcp_relay(dhcp_servers: tuple[str]) -> bool:
            return dhcp_servers and dhcp_servers[0] == Provider.PRIMARY_DHCP_SERVER and dhcp_servers[1] in Provider.SECONDARY_DHCP_SERVERS
        
        def check_vlan_id_dhcp_relay(vlan_ids_list: list[str]) -> bool:
            return any([i != "" and self.__untagged_vlan_id in range(int(i.split("-")[0]), int(i.split("-")[-1]) + 1) for i in vlan_ids_list])
        
        # get servers and vlan ids
        dhcp_servers, vlan_ids = self._switch_manager.get_dhcp_relay()

        # vlan_ids = -1 means switch doesn't have to have dhcp relay
        if vlan_ids == -1:
            # decide only basing on servers
            if check_servers_dhcp_relay(dhcp_servers):
                self.__dhcp_relay_ok = True
            else:
                self.__incorrect_dhcp_relay = True
        # for switches with dchp relay, ok if dhcp servers are correct and vlan id is enabled in dhcp relay
        elif check_servers_dhcp_relay(dhcp_servers) and check_vlan_id_dhcp_relay(vlan_ids):
            self.__dhcp_relay_ok = True
        # incorrect otherwise
        else:
            self.__incorrect_dhcp_relay = True

    # check access profile options on port
    def __check_acl(self) -> None:
        # get acl entries on port in hex notation
        hex_entries = self._switch_manager.get_port_acl()
        
        # if there's less than needed entries
        if len(hex_entries) < 2:
            self.__no_acl = True
        # if at least one entry doesn't match ip
        elif any([self.__get_ip_from_acl(i) != self._record_data["ip"] for i in hex_entries]):
            self.__wrong_acl = True
        # if everything is ok
        else:
            self.__acl_ok = True

    # transform acl entry to ip, entry should has 8 hex symbols
    def __get_ip_from_acl(self, acl_entry: str) -> str:
        return ".".join([str(int(acl_entry[2*i : 2*i+2], 16)) for i in range(4)])
    
    # check port and mark flags
    def __check_port(self) -> None:
        # check port, get its type, settings and status, linkdown_status is actual if port is enabled
        self.__fiber_port, self.__port_disabled, self.__speed_settings, self.__linkdown_status, speed = self._switch_manager.get_port_link()
        
        # if there's link
        if not self.__port_disabled and not self.__linkdown_status:
            # check if speed is satisfying, cable diag needed if not
            if not (speed == CitySwitch.NORMAL_SPEED[True] or not self.__gigabit and speed == CitySwitch.NORMAL_SPEED[False]):
                self.__need_to_cable_diag = True
                self.__lower_speed = speed
            # otherwise it's ok
            else: 
                self.__link_ok = True
    
    # check crc errors
    def __check_crc(self) -> None:
        # get numbers of rx crc errors, will be zero if OK
        self.__crc_errors = self._switch_manager.get_crc_errors_port()
        
        # flag if crc ok
        if self.__crc_errors == 0:
            self.__crc_ok = True
    
    # perform cable diagnostics
    def __try_cable_diag(self) -> None:
        # can't perform is its fiber (SFP) port
        if self.__fiber_port:
            return
        
        # result can be different pairs or just status
        res = self._switch_manager.cable_diag()
        
        # if result is list, it marks opened pairs
        if isinstance(res, list):
            self.__open_cable_pairs = res
        # if result is string, it's just status
        else:
            self.__cable_diag_status = res
    
    # check if port is flapping
    def __check_log(self) -> None:
        # get flapping count and last flap remoteness in time
        try:
            count_flapping, last_flap_remoteness = self._switch_manager.get_log_port_flapping()
        except ValueError:
            self.__invalid_log_time = True
            return
        
        # if flapping is too often, mark flag and try cable diag afterall
        if last_flap_remoteness < CitySwitch.LAST_FLAP_MAX_MINUTE_REMOTENESS and count_flapping >= CitySwitch.MIN_COUNT_FLAPPING:
            self.__port_flapping = True
            self.__need_to_cable_diag = True
    
    # mac address diagnostics
    @override
    def _check_mac(self) -> None:
        # get mac addresses and main flags using base method
        super()._check_mac()
        
        # error when there's no mac, cable diag needed
        if self._no_mac:
            self.__need_to_cable_diag = True
        
        # check if port security is enabled
        self.__port_security = self._switch_manager.get_port_security()
    
    # check packet bytes and calculate megabit
    def __check_packets(self) -> None:
        # get rx and tx bytes
        self.__rx_bytes, self.__tx_bytes = self._switch_manager.get_packets_port()
        
        # calculate to megabit
        self.__rx_megabit = super()._byte_to_megabit(self.__rx_bytes)
        self.__tx_megabit = super()._byte_to_megabit(self.__tx_bytes)
        
        # set flag that packets successfully checked
        self.__packets_ok = True
    
    # check for direct public ip and find its gateway where arp should be
    @override
    def _find_actual_gateway(self) -> None:
        # init L3 manager by user record's gateway if ip is local
        if not self.__direct_public_ip:
            self._gateway_manager = L3Manager(self._record_data["gateway"], self._record_data["ip"], self.__print_output)
            return
        
        # on Lensoveta 23, define gateway address for direct public ip
        if self._record_data["street"] == Provider.LENSOVETA_ADDRESS_GATEWAY["street"] and self._record_data["house"] == Provider.LENSOVETA_ADDRESS_GATEWAY["house"]:
            self._gateway_manager = L3Manager(Provider.LENSOVETA_ADDRESS_GATEWAY["gateway"], self._record_data["ip"], self.__print_output)
            return
        
        # otherwise, find default gateway address on switch
        gateway = self._switch_manager.get_default_gateway()
        
        # may need from 1 to 3 iterations
        for _ in range(CitySwitch.MAX_HOPS_DIRECT_PUBLIC_IP):
            # create or update L3 manager and find ip route for direct public ip
            self._gateway_manager = L3Manager(gateway, self._record_data["ip"], self.__print_output)
            gateway = self._gateway_manager.check_ip_route()

            # if nothing found, mark flag and keep current L3 manager
            if not gateway:
                self.__ip_route_not_found = True
                return
            
            # break if self-route found
            elif gateway == self._record_data["ip"]:
                return
            
            # delete previous and continue with new L3 manager if new next hop found
            del self._gateway_manager
        
        # if self-route not found in 3 iterations, mark error flag
        self.__ip_route_not_found = True
    
    # check if vlan's ip interface on L3 matches user's subnet
    @override
    def _check_vlan_subnet(self) -> None:
        # can't diagnose if don't have exact untagged vlan
        if not self.__untagged_vlan_id:
            return
        
        # base method checks ip interface with by vlan and compare with subnet
        # ipif name is vlan name for local ip and last 2 octets of gateway for direct public ip
        super()._check_user_subnet_matches_ip_interface(self.__untagged_vlan_id, self.__switch_vlans[self.__untagged_vlan_id],
                                                        self._record_data["gateway"][-7:] if self.__direct_public_ip 
                                                                    else self.__switch_vlans[self.__untagged_vlan_id],
                                                        self._record_data["gateway"], self.__mask_length)
    
    # result of L2 and L3 diagnostics
    @override
    def _result_L2_L3(self) -> None:
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
            print("Линк", self.__lower_speed, "вместо", CitySwitch.NORMAL_SPEED[self.__gigabit])
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
            if self._no_mac:
                print("Нет мака на порту")
            elif self._many_macs:
                print("Маков на порту:", self._many_macs)
            elif self._mac_ok:
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
        for ind, status in enumerate(CitySwitch.VLAN_STATUSES):
            if status in self.__port_vlans and (ind != 0 or not self.__untagged_vlan_id):
                print("Влан", ", ".join(map(str, self.__port_vlans[status])), "в", status)
        if self.__untagged_vlan_id:
            if self.__user_vlan_instead_of_direct_public_vlan:
                print(f"Назначен юзерский влан вместо {Provider.DIRECT_PUBLIC_VLAN}")
            elif self.__direct_public_vlan_instead_of_user_vlan:
                print(f"Назначен влан {Provider.DIRECT_PUBLIC_VLAN} вместо юзерского")
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
        if self._no_arp:
            print("ARP не найдена")
        elif self._arp_on_unknown_mac:
            print("ARP найдена на неизвестный мак:", self._arp_on_unknown_mac)
        elif self._arp_ok:
            print("ARP OK")
        # if found arp by mac with wrong ip addresses, is possible even if arp ok or unknown mac
        if self._ip_incorrect_arp_on_mac:
            print("По маку на порту найдена неверная ARP:", ", ".join(self._ip_incorrect_arp_on_mac))
        # if mac was checked, print found or not
        if self._need_to_check_mac_on_L3:
            if self._no_mac_on_L3:
                print("Мак не виден на L3")
            else:
                print("Мак виден на L3")
        
        # ip interface on L3: if not found or subnet for vlan is wrong
        if self._ip_interface_not_found:
            print("Не найден интерфейс для юзерского влана")
        elif self._ip_interface_wrong_subnet:
            print("Подсеть интерфейса для влана на порту не соответствует подсети из карточки")
    