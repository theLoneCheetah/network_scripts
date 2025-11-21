#!/usr/bin/python3
from enum import Enum
from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv4Network, AddressValueError
from collections import defaultdict
import pymysql.cursors
import pexpect
import re
import sys
import os
from dotenv import load_dotenv, find_dotenv


# convert fields from database to useful names
class Const(Enum):
    key_field = {"Vznos": "payment",
                 "IP": "ip",
                 "Masck": "mask",
                 "Gate": "gateway",
                 "switchP": "switch",
                 "PortP": "port",
                 "dhcp_type": "dhcp",
                 "Add_IP": "public_ip",
                 "Number_serv": "nserv",
                 "Number_net": "nnet"}
    key_output = {"ip": "IP-адрес",
                  "mask": "Маска",
                  "gateway": "Шлюз",
                  "switch": "Свитч статич.",
                  "port": "Порт статич.",
                  "dhcp": "Тип DHCP",
                  "public_ip": "Внешний IP",
                  "nserv": "Nserv",
                  "nnet": "Nnet"}
    usernum = "Number"
    
    # speed by payments (vznos), country payments, 555 is an exception
    new_payment = 555
    fast_ethernet = {52, 53, 54, 301, 303, 330, 400, 490, 492, 494, 497, 503, 508, 509, 580, 582, 583, 586, 592, 598, 666, 667, 1000, 1300, 2000}
    gigabit_ethernet = {650, 652, 653, 656, 662, 668, 720, 722, 723, 726, 732, 738, 950, 951, 952, 953, 956, 962, 968, 1330}
    old_payment = {10, 48, 49, 95, 96, 97, 98, 99}
    country = {801, 1001, 1006, 1012, 1501, 1506, 1512, 2001, 2006, 2012}
    max_known_payment = 2099   # more than 2100 let's decide there's only gigabit
    
    # network has nnets and nservs from 1 to 1016 now
    last_nserv_nnet = 1016
    last_port = 52
    
    number_fields_limits = {"port": last_port, "dhcp": 1, "nserv": last_nserv_nnet, "nnet": last_nserv_nnet}
    ip_fields = {"ip", "mask", "gateway", "switch", "public_ip"}
    
    # network local addresses are now in 10.131.x.x-10.146.x.x subnets
    first_local_ip = IPv4Address("10.131.0.0")
    last_local_ip = IPv4Address("10.146.255.255")
    switch_other_local_subnet = IPv4Network("172.16.60.0/24")
    
    # set of network public subnets
    public_subnets = {IPv4Network(subnet, strict=False) for subnet in ["178.252.127.253/18", "146.66.191.253/19", "146.66.207.253/20"]}
    
    # all the commmands and patterns for re
    commands = {"DES-3028": {}, "DES-3052": {}, "DGS-1210-28/ME": {}, "DGS-1210-52/ME": {}, "DGS-3000-24TC": {}, "DGS-3000-26TC": {}, "DGS-3120-24TC": {}, "DGS-3200-24": {}, "DES-3200-28": {}, "DES-3526": {}, \
    "DGS-3620-28TC": {}," DGS-3620-28SC": {}, "DGS-3627G": {}, "DGS-3630-28SC": {}}
    
    # variables and expressions while diagnosting
    normal_speed = {False: "100M/Full", True: "1000M/Full"}
    vlan_statuses = ["Untagged", "Tagged", "Forbidden", "Dynamic"]
    vlan404 = 404
    iptv_vlan_skipping = 778

# class to get data from the database
class DatabaseManager:
    # init data and connect to database
    def __init__(self):
        self.__SERVER = os.getenv("DB_SERVER")
        self.__DATABASE = os.getenv("DB_NAME")
        self.__USER = os.getenv("DB_USER")
        self.__PASSWORD = os.getenv("DB_PASSWORD")
        self.__CHARSET = os.getenv("DB_CHARSET")
        
        # basic query gets all important fields
        self.__get_query = "SELECT Number, Vznos, IP, Masck, Gate, switchP, PortP, dhcp_type, Add_IP, Number_serv, Number_net FROM users WHERE Number = %s"
        self.__start_connection()
    
    # start
    def __start_connection(self):
        print("Connecting to database...")
        self.__connection = pymysql.connect(host=self.__SERVER,
                                 user=self.__USER,
                                 password=self.__PASSWORD,
                                 db=self.__DATABASE,
                                 charset=self.__CHARSET,
                                 cursorclass=pymysql.cursors.DictCursor)
        print("Success")
    
    # get data about this user
    def get_record(self, usernum):
        with self.__connection.cursor() as cursor:
            cursor.execute(self.__get_query, (usernum,))
            return cursor.fetchone()
    
    # end
    def __close_connection(self):
        print("Closing connection...")
        self.__connection.close()
        print("Success")
    
    # delete
    def __del__(self):
        self.__close_connection()


# abstract class to L2-L3 managers
class NetworkManager(ABC):
    # init by ip and connect with the same username and password
    def __init__(self, ipaddress):
        self.__ipaddress = ipaddress
        self.__USERNAME = os.getenv("NET_USER")
        self.__PASSWORD = os.getenv("NET_PASSWORD")
        
        self.__start_connection()
    
    # start
    def __start_connection(self):
        print("Connecting to switch...")
        # protected atribute, it will be inherited
        self._session = pexpect.spawn(f"telnet {self.__ipaddress}")#, logfile=sys.stdout.buffer)
        
        self._session.expect("User(N|n)ame:")
        self._session.sendline(self.__USERNAME)
        self._session.expect("Pass(W|w)ord:")
        self._session.sendline(self.__PASSWORD)
        self._session.expect("#")
        
        self._session.sendline("disable clipaging")
        self._session.expect("#")
        
        print("Success")
    
    # end
    def __close_connection(self):
        print("Closing connection...")
        self._session.sendline("enable clipaging")
        self._session.expect("#")
        self._session.close()
        print("Success")
    
    # delete
    def __del__(self):
        self.__close_connection()

# class to connect and communicate with L2
class L2Manager(NetworkManager):
    # show ports and catch groups
    def __show_port(self, port):
        # command
        self._session.sendline(f"show ports {port}")
        
        # first expression for single type port, second for combo port
        index = self._session.expect([rf"{port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#", rf"{port}\(C\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*{port}\(F\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#"])
        # 1210: index = self._session.expect([rf"{port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled).*#", rf"{port}\(C\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled).*{port}\(F\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled).*#"])
        
        # if it's combo port and active type is fiber
        if index == 1 and (self._session.match.group(10) or self._session.match.group(1).decode("utf-8") == "Disabled"):
            return (True, *self._session.match.group(6, 7, 9, 10))
        # otherwise
        return (False, *self._session.match.group(1, 2, 4, 5))
    
    # handler to check and return info about port
    def get_port_link(self, port):
        # get all important parts including port type
        fiber, state, settings, linkdown, linkup = self.__show_port(port)
        
        # modify to useful form
        state = state.decode("utf-8") == "Disabled"   # boolean
        settings = None if settings.decode("utf-8") == "Auto" else settings.decode("utf-8")   # if resctricted
        linkdown = linkdown.decode("utf-8") if linkdown and not state else None   # if down with enabled port
        linkup = linkup.decode("utf-8") if linkup else None   # speed if up
        
        # return all modified
        return (fiber, state, settings, linkdown, linkup)
    
    # cable diagnostics
    def cable_diag(self, port):
        # command
        self._session.sendline(f"cable_diag ports {port}")
        self._session.expect("#")

        # save output and test different patterns
        temp = self._session.before.decode("utf-8")
        match = re.search(rf"({port}\s+(\S+)\s+(Link Up|Link Down)\s+Pair(\d)\s+([A-Za-z]+)\s+at\s+(\d+)\s+M\s+(-|\d+))|({port}\s+(\S+)\s+(Link Up|Link Down)\s+([A-Za-z ]+)\s+(-|\d+))", temp)
        
        # if it's patterns with pairs' lengths, return list
        if match.group(1):
            return re.findall(r"Pair(\d)\s+([A-Za-z]+)\s+at\s+(\d+)\s+M", temp)
        # if it's just a diagnose, return string
        return match.group(11)
    
    # get all vlans on switch
    def get_switch_vlans(self):
        # command
        self._session.sendline("show vlan")
        self._session.expect("#")
        
        # get vlan_id: vlan_name
        return {int(vlan_id): vlan_name for vlan_id, vlan_name in re.findall(r"VID\s+:\s+(\d+)\s+VLAN Name\s+:\s+(\S+)", self._session.before.decode("utf-8"))}
        # 1210: return {int(vlan_id): vlan_name for vlan_id, vlan_name in re.findall(r"VID\s+:\s+(\d+)\s+VLAN NAME\s+:\s+(\S+)", self._session.before.decode("utf-8"))}
    
    # get vlans on port
    def get_port_vlans(self, port):
        # command
        self._session.sendline(f"show vlan ports {port}")
        self._session.expect("#")
        
        # dictionary for vlans with statuses as keys
        port_vlans = defaultdict(list)
        
        # parse entry, X means actual status
        for match in re.findall(r"(\d+)+\s+([X-])\s+([X-])\s+([X-])\s+([X-])", self._session.before.decode("utf-8")):
            pos = match.index("X") - 1
            if int(match[0]) != Const.iptv_vlan_skipping.value:   # skip old iptv vlan
                port_vlans[Const.vlan_statuses.value[pos]].append(int(match[0]))
        
        # return complete dictionary
        return port_vlans
    
    # get acl options on port from overall output
    def get_port_acl(self, port):
        # command
        self._session.sendline("show access_profile")
        self._session.expect("#")
        
        # catch and return two entries of user port's rules
        return re.findall(rf"Ports\s+:\s+{port}\s+Mode\s+:\s+Permit[\s\S]*?0x([a-z\d]{{8}})\s+0xffffffff", self._session.before.decode("utf-8"))

# class to communicate with L3
class L3Manager(NetworkManager):
    def check_arpentry():
        pass

# main class to handle all work
class MainHandler:
    def __init__(self, usernum):   # init by usernum
        self.__usernum = usernum
        self.__db_manager = None
        self.__switch_manager = None
        self.__gate_manager = None
        
        self.__record_data = {}   # user record from database
        self.__correctly_filled = {}   # -1 if data from record is incorrect, 0 if empty, 1 if correct
        
        # flags for country, speed and unknown payment
        self.__country = False
        self.__gigabit = False
        self.__inactive_payment = False
        self.__unknown_payment = False
        
        # flags that shows how many fields are filled
        self.__switch_port = False
        self.__ip_mask_gateway = False   # important only if __switch_port is True
        self.__direct_public_ip = False
        
        # flags for errors in diagnostics of the database record
        self.__impossible_mask = False
        self.__ip_out_of_subnet = False
        self.__incorrect_indirect_public_ip = False
        self.__different_ip_public_ip = False
        self.__incorrect_gateway = False
        self.__incorrect_switch = False
        
        # flags for diagnostics of L2 and L3
        self.__fiber_port = False
        self.__switch_vlans = {}
        self.__have_vlan404 = False
        self.__untagged_vlan_id = -1
        self.__port_vlans = {}   # VID: status
        
        # flags for errors in diagnostics of L2
        self.__port_disabled = False
        self.__speed_settings = None
        self.__linkdown_status = None
        self.__lower_speed = None
        self.__open_cable_pairs = []
        self.__cable_diag_status = None
        self.__no_vlan = False
        self.__user_vlan_instead_of_vlan404 = False
        self.__vlan404_instead_of_user_vlan = False
        self.__no_acl = False
        self.__wrong_acl = False
    
    ##### DATABASE AND USER CARD PART #####
    
    # check payment (vznos)
    def __check_payment(self):
        # if it's country, speed is not necessary
        if self.__record_data["payment"] in Const.country.value:
            self.__country = True
        # if it's new user, ask for speed
        elif self.__record_data["payment"] == Const.new_payment.value:
            self.__gigabit = input(f"Vznos is {Const.new_payment.value}. Gigabit? (y/n) ").lower() == "y"
        # 100 Mbit if payment is known
        elif self.__record_data["payment"] in Const.fast_ethernet.value:
            self.__gigabit = False
        # 1 Gbit if payment is known or more than limit
        elif self.__record_data["payment"] in Const.gigabit_ethernet.value or self.__record_data["payment"] > Const.max_known_payment.value:
            self.__gigabit = True
        # user is inactive, didn't pay or disconnected
        elif self.__record_data["payment"] in Const.old_payment.value:
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
    def __get_mask_length(self):
        # get binary notation
        bin_mask = f"{IPv4Address(self.__record_data['mask']):b}"
        # mask should contain 1s, then 0s
        match = re.search("^(1{16,})0{2,}$", bin_mask)
        
        # if mask matches, return its length
        if match:
            return len(match.group(1))
        return -1
    
    # check if ip address matches subnet
    def __check_ip_in_subnet(self, mask_length):
        subnet = IPv4Network(f"{self.__record_data['gateway']}/{mask_length}", strict=False)
        return IPv4Address(self.__record_data["ip"]) in subnet
    
    # check if address is in local range, usually gateway, sometimes switch
    def __check_local_ip(self, address=None):
        if address is None:
            address = self.__record_data["gateway"]
        return int(Const.first_local_ip.value) <= int(IPv4Address(address)) <= int(Const.last_local_ip.value)
    
    # check if address is in public range, usually gateway, sometimes indirect public_ip
    def __check_public_ip(self, address=None):
        if address is None:
            address = self.__record_data["gateway"]
        return any(IPv4Address(address) in subnet for subnet in Const.public_subnets.value)
    
    # check switch ip, it can be in usual local range or in one special local subnet
    def __check_switch_ip(self):
        return self.__check_local_ip(self.__record_data["switch"]) or IPv4Address(self.__record_data["switch"]) in Const.switch_other_local_subnet.value
    
    # function to control user's database record checking
    def __check_user_card(self):
        try:
            # connect and get record from database
            self.__db_manager = DatabaseManager()
            dict_data = self.__db_manager.get_record(self.__usernum)
            self.__record_data = {Const.key_field.value[key]: value for key, value in dict_data.items() if key != Const.usernum.value}
            
            # check payment to choose county/city and speed
            self.__check_payment()
            
            ########## TO BE WRITTEN...
            if self.__country:
                raise Exception("It's country! Help!")
            
            # check and make a note about numeric fields
            for field, limit in Const.number_fields_limits.value.items():
                self.__correctly_filled[field] = self.__check_number_fields(field, limit)
            
            # check and make a note about ip fields
            for field in Const.ip_fields.value:
                self.__correctly_filled[field] = self.__check_ip_fields(field)
            
            # check switch ip
            if self.__correctly_filled["switch"] == 1:
                # if switch isn't correct, set a flag
                if not self.__check_switch_ip():
                    self.__incorrect_switch = True
                # if switch and port are correct, L2 diagnostics is possible
                elif self.__correctly_filled["port"] == 1:
                    self.__switch_port = True
            
            # check mask and subnet
            if self.__correctly_filled["mask"] == 1:
                mask_length = self.__get_mask_length()
                # set a special flag if mask's address doesn't suit to regular mask
                if mask_length == -1:
                    self.__impossible_mask = True
                
                # if ip and gateway exist, it's possible to check subnet
                elif self.__correctly_filled["ip"] == 1 and self.__correctly_filled["gateway"] == 1:
                    # make sure ip is in the subnet, or set a flag
                    if not self.__check_ip_in_subnet(mask_length):
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
                        self.__incorrect_gateway = True
                    
                    # if there was no errors, acl and L3 diagnostics is possible
                    if not any([self.__ip_out_of_subnet, self.__incorrect_indirect_public_ip, self.__different_ip_public_ip, self.__incorrect_gateway]):
                        self.__ip_mask_gateway = True
        
        except Exception as err:   # exception while checking record
            print("Exception while working with the database record:", err, sep="\n")
        
        finally:   # always close connection and delete database manager
            del self.__db_manager
    
    # result of database record diagnostics
    def __result_user_card(self):
        all_correct = True
        
        print("-" * 20)
        print("ДИАГНОСТИКА КАРТОЧКИ:")
        
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
            print("Не заполнены поля:", ", ".join(name for key, name in Const.key_output.value.items() if key != "public_ip" and self.__correctly_filled[key] == 0))
            all_correct = False
        
        # print obviously incorrect fields
        if any(value == -1 for key, value in self.__correctly_filled.items()):
            print("Неверно заполнены поля:", ", ".join(name for key, name in Const.key_output.value.items() if self.__correctly_filled[key] == -1))
            all_correct = False
        
        # switch error separately
        if self.__incorrect_switch:
           print("Некорректный адрес свитча")
           all_correct = False
        
        # subnet errors alternatively
        if self.__impossible_mask:
            print("Невозможная маска")
        elif self.__incorrect_gateway:
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
    
    # check port and mark flags
    def __check_port(self):
        # check port, get its type, settings and status, linkdown_status is actual if port is enabled
        self.__fiber_port, self.__port_disabled, self.__speed_settings, self.__linkdown_status, speed = self.__switch_manager.get_port_link(self.__record_data["port"])
        
        # check if speed is satisfying
        if speed != Const.normal_speed.value[self.__gigabit]:
            self.__lower_speed = speed
    
    # perform cable diagnostics
    def __try_cable_diag(self):
        # result can be different pairs or just status
        res = self.__switch_manager.cable_diag(self.__record_data["port"])
        
        # if result is list, it marks opened pairs
        if isinstance(res, list):
            self.__open_cable_pairs = res
        # if result is string, it's just status
        else:
            self.__cable_diag_status = res
    
    # check vlans on switch and on port
    def __check_vlan(self):
        # get switch vlans
        self.__switch_vlans = self.__switch_manager.get_switch_vlans()
        self.__have_vlan404 = Const.vlan404.value in self.__switch_vlans
        
        # get port vlans
        self.__port_vlans = self.__switch_manager.get_port_vlans(self.__record_data["port"])
        
        # no_vlan flag if port has no vlans of any status
        if not self.__port_vlans:
            self.__no_vlan = True
        
        # check if there's only 1 untagged vlan, remember it
        elif Const.vlan_statuses.value[0] in self.__port_vlans and len(self.__port_vlans[Const.vlan_statuses.value[0]]) == 1:
            self.__untagged_vlan_id = self.__port_vlans[Const.vlan_statuses.value[0]][0]
            
            # mark flag if port doesn't have vlan404
            if self.__direct_public_ip and self.__have_vlan404 and self.__untagged_vlan_id != Const.vlan404.value:
                self.__user_vlan_instead_of_vlan404 = True
            # mark flag if port doesn't have user vlan
            elif not self.__direct_public_ip and self.__untagged_vlan_id == Const.vlan404.value:
                self.__vlan404_instead_of_user_vlan = True
    
    # transform acl entry to ip, entry should has 8 hex symbols
    def __get_ip_from_acl(self, acl_entry):
        return ".".join([str(int(acl_entry[2*i : 2*i+2], 16)) for i in range(4)])
    
    # check access profile options on port
    def __check_acl(self):
        # get acl entries on port in hex notation
        hex_entries = self.__switch_manager.get_port_acl(self.__record_data["port"])
        
        # if there's less than needed entries
        if len(hex_entries) < 2:
            self.__no_acl = True
        # if at least one entry doesn't match ip
        elif any([self.__get_ip_from_acl(i) != self.__record_data["ip"] for i in hex_entries]):
            self.__wrong_acl = True
    
    # function to control diagnosting L2 and L3
    def __check_L2_L3(self):
        try:
            if not self.__switch_port:   # exception if there's no data
                raise Exception("Unable to diagnose L2: don't have switch and port")
            
            # connect to switch only if switch and port are known
            self.__switch_manager = L2Manager(self.__record_data["switch"])
            
            # if subnet is correct, check vlan and acl
            if self.__ip_mask_gateway:
                # check vlan
                self.__check_vlan()
                
                # check acl
                self.__check_acl()
            
            # check port
            self.__check_port()
            
            # if link is down not because of disabled port, try cab diag
            if self.__linkdown_status:
                self.__try_cable_diag()
                # exception to skip the code block
                raise Exception("Unable to diagnose port details: don't have link")
            
            
        except Exception as err:
            if re.match("Unable to diagnose", str(err)):   # unable exception
                print(err)
            else:   # exception while working with L2 or L3
                print("Exception while working with equipment:", err, sep="\n")
        
        finally:
            # always close connection and delete L2 and L3 managers
            if self.__switch_manager:
                del self.__switch_manager
            if self.__gate_manager:
                del self.__gate_manager
        
        """
        finally:
            # always close connection and delete L2 and L3 managers
            if self.__switch_manager:
                del self.__switch_manager
            if self.__gate_manager:
                del self.__gate_manager
        """
    
    # result of L2 and L3 diagnostics
    def __result_L2_L3(self):
        print("-" * 20)
        print("ДИАГНОСТИКА ОБОРУДОВАНИЯ:")
        
        # port: speed settings firstly, then status and speed
        if self.__speed_settings:
            print("Скорость ограничена вручную в", self.__speed_settings)
        if self.__port_disabled:
            print("Порт выключен")
        elif self.__linkdown_status:
            print("Состояние порта:", self.__linkdown_status)
        elif self.__lower_speed:
            print("Линк", self.__lower_speed, "вместо", Const.normal_speed.value[self.__gigabit])
        else:
            print("Линк ОК")
        
        # cable diag: just status or a list of open pairs
        if self.__linkdown_status:
            if self.__cable_diag_status:
                print("Кабдиаг", self.__cable_diag_status)
            else:
                # list has records as [pair, status, meter]
                print("Кабдиаг", ", ".join(map(lambda x: f"{x[0]}п {x[2]}м {x[1]}", self.__open_cable_pairs))) 
        
        # vlan: no vlan, wrong tags, wrong untagged vlan
        vlan_error = False
        if self.__no_vlan:
            print("Нет влана на порту")
        for ind, status in enumerate(Const.vlan_statuses.value):
            if status in self.__port_vlans and (ind != 0 or self.__untagged_vlan_id == -1):
                vlan_error = True
                print("Влан", ", ".join(map(str, self.__port_vlans[status])), "в", status)
        if self.__untagged_vlan_id != -1:
            if self.__user_vlan_instead_of_vlan404:
                print(f"Назначен юзерский влан вместо {Const.vlan404.value}")
            elif self.__vlan404_instead_of_user_vlan:
                print(f"Назначен влан {Const.vlan404.value} вместо юзерского")
            elif not vlan_error:
                print("Влан ок")
        
        # acl: no than needed or wrong entries
        if self.__no_acl:
            print("Отсутствует правило ACL")
        elif self.__wrong_acl:
            print("ACL не соответствует IP")
        else:
            print("ACL ок")
    
    # main function
    def check_all(self):
        self.__check_user_card()
        self.__check_L2_L3()
        
        self.__result_user_card()
        self.__result_L2_L3()
    
    # print all necessary fields
    def print_record(self):
        print("-" * 20)
        print(f"{Const.usernum.name}:{' '*(12-len(Const.usernum.name))}{self.__usernum}")
        for key in self.__record_data:
            print(f"{key}:{' '*(12-len(key))}{self.__record_data[key]}")
        print("-" * 20)


def main():
    load_dotenv(find_dotenv())
    usernum = int(input("Usernum: "))
    handler = MainHandler(usernum)
    handler.check_all()

if __name__ == "__main__":
    main()
