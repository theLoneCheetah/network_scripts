#!/usr/bin/python3
import pymysql.cursors
import pexpect
import re
import sys
import os
import time
from dotenv import load_dotenv, find_dotenv
from enum import Enum
from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv4Network, AddressValueError
from collections import defaultdict
from datetime import datetime
import commands   # user's lib


##### PROGRAM CONSTANTS #####

class Const(Enum):
    # convert fields from database to useful program names
    key_field = {"Vznos": "payment",
                 "IP": "ip",
                 "Masck": "mask",
                 "Gate": "gateway",
                 "switchP": "switch",
                 "PortP": "port",
                 "dhcp_type": "dhcp",
                 "Add_IP": "public_ip",
                 "Number_serv": "nserv",
                 "Number_net": "nnet",
                 "Street": "street",
                 "House": "house"}
    # convert program names to the form used in workspace cards
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
    
    # fields checking limits
    number_fields_limits = {"port": last_port, "dhcp": 1, "nserv": last_nserv_nnet, "nnet": last_nserv_nnet}
    ip_fields = {"ip", "mask", "gateway", "switch", "public_ip"}
    
    # network local addresses are now in 10.131.x.x-10.146.x.x subnets
    first_local_ip = IPv4Address("10.131.0.0")
    last_local_ip = IPv4Address("10.146.255.255")
    switch_other_local_subnet = IPv4Network("172.16.60.0/24")
    
    # set of network public subnets
    public_subnets = {IPv4Network(subnet, strict=False) for subnet in ["178.252.127.253/18", "146.66.191.253/19", "146.66.207.253/20"]}
    
    # variables and expressions while diagnosting
    normal_speed = {False: "100M/Full", True: "1000M/Full"}
    vlan_statuses = ["Untagged", "Tagged", "Forbidden", "Dynamic", "RadiusAssigned"]
    vlan404 = 404
    iptv_vlan_skipping = 778
    max_minute_range_port_flapping = 10
    last_flap_max_minute_remoteness = 2
    min_count_flapping = 20
    
    # types of cli to identify model
    cli_types = ["d-link", "cisco"]
    
    # on Lensoveta 23 OSPF protocol is used, default gateway address doesn't have static ip route
    lensoveta_address_gateway = {"street": 33, "house": "23", "gateway": "10.132.59.204"}


##### CLASS TO GET DATA FROM THE DATABASE #####

class DatabaseManager:
    # init data and connect to database
    def __init__(self):
        self.__SERVER = os.getenv("DB_SERVER")
        self.__DATABASE = os.getenv("DB_NAME")
        self.__USER = os.getenv("DB_USER")
        self.__PASSWORD = os.getenv("DB_PASSWORD")
        self.__CHARSET = os.getenv("DB_CHARSET")
        
        # basic query gets all important fields
        self.__get_query = "SELECT Number, Vznos, IP, Masck, Gate, switchP, PortP, dhcp_type, Add_IP, Number_serv, Number_net, Street, House FROM users WHERE Number = %s"
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
    
    # find users on this switch and port
    def get_usernum_by_switch_port(self, switch, port):
        with self.__connection.cursor() as cursor:
            cursor.execute("SELECT Number FROM users WHERE switchP = %s AND PortP = %s", (switch, port))
            return [row[Const.usernum.value] for row in cursor.fetchall()]
    
    # find users with this ip
    def get_usernum_by_ip(self, ip):
        with self.__connection.cursor() as cursor:
            cursor.execute("SELECT Number FROM users WHERE IP = %s", (ip,))
            return [row[Const.usernum.value] for row in cursor.fetchall()]
    
    # end
    def __close_connection(self):
        print("Closing connection...")
        self.__connection.close()
        print("Success")
    
    # delete
    def __del__(self):
        self.__close_connection()


##### ABSTRACT CLASS FOR L2-L3 MANAGERS #####

class NetworkManager(ABC):
    # init by ip and connect with the same username and password
    def __init__(self, ipaddress):
        # define ip and get connection's environment
        self.__ipaddress = ipaddress
        self.__USERNAME = os.getenv("NET_USER")
        self.__PASSWORD = os.getenv("NET_PASSWORD")
        
        # switch model name from the defined dict and commands for clipaging
        self._model = ""
        self._ports = 0
        self._turn_clipaging = {}
        
        # connect
        self.__start_connection()
    
    # try to figure out switch model name
    def __get_model(self, cli_type):
        # try to show mode info
        command_regex = commands.show_model(cli_type)
        self._session.sendline(command_regex["command"])
        
        # expect output's ending and continuation
        index = self._session.expect(["CTRL", "#"])
        temp = self._session.before.decode("utf-8")
        
        # quit if needed
        if index == 0:
            self._session.send("q")
            self._session.expect("#")
        
        # try to find device model
        match = re.search(command_regex["regex"], temp)
        return match.group(1) if match else None
    
    # start
    def __start_connection(self):
        print("Connecting to equipment...")
        # protected atribute, it will be inherited
        self._session = pexpect.spawn(f"telnet {self.__ipaddress}", logfile=sys.stdout.buffer)
        
        self._session.expect("(U|u)ser(N|n)ame:")
        self._session.sendline(self.__USERNAME)
        self._session.expect("(P|p)ass(W|w)ord:")
        self._session.sendline(self.__PASSWORD)
        self._session.expect("#")
        
        # get through two types of cli to get device model
        for cli_type in Const.cli_types.value:
            model = self.__get_model(cli_type)
            if model:
               self._model = model
               break
        # raise exception if model unknown
        else:
            raise Exception(f"Unable to diagnose: unknown switch model with ip {self.__ipaddress}")
        
        # turn off clipaging to see commands' whole results
        self._turn_clipaging = commands.clipaging(self._model)
        self._session.sendline(self._turn_clipaging["disable"])
        self._session.expect("#")
        
        print("Success")
    
    # end
    def __close_connection(self):
        print("Closing connection...")
        
        # restore clipaging on switch
        self._session.sendline(self._turn_clipaging["enable"])
        self._session.expect("#")
        
        self._session.close()
        print("Success")
    
    # delete
    def __del__(self):
        self.__close_connection()


##### CLASS TO COMMUNICATE WITH L2 SWITCH #####

class L2Manager(NetworkManager):
    # L2 manager inits by user port and base constructor
    def __init__(self, ipaddress, user_port):
        super().__init__(ipaddress)
        self.__ports = commands.switches[self._model]["ports"]
        self._model = commands.switches[self._model]["base_switch"]
        self.__user_port = user_port
    
    def check_port_in_portlist(self):
        return self.__user_port <= self.__ports
    
    # show ports and catch groups
    def __show_port(self):
        # command
        command_regex = commands.show_ports(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        
        # try expressions for simple and combo ports
        index = self._session.expect(command_regex["regex"])
        
        # save match and quit dynamic page on some switches
        match = self._session.match
        if self._model == "DGS-3200-24" or self._model == "DES-3200-28":
            self._session.send("q")
            self._session.expect("#")
        
        # if it's combo port and active type is fiber
        if index == 1 and (match.group(10) or match.group(1).decode("utf-8") == "Disabled"):
            return (True, *match.group(6, 7, 9, 10))
        # otherwise
        return (False, *match.group(1, 2, 4, 5))
    
    # handler to check and return info about port
    def get_port_link(self):
        # get all important parts including port type
        fiber, state, settings, linkdown, linkup = self.__show_port()
        
        # modify to useful form
        state = state.decode("utf-8") == "Disabled"   # boolean
        settings = None if settings.decode("utf-8") == "Auto" else settings.decode("utf-8")   # if resctricted
        linkdown = linkdown.decode("utf-8") if linkdown and not state else None   # if down with enabled port
        linkup = linkup.decode("utf-8") if linkup else None   # speed if up
        
        # return all modified
        return (fiber, state, settings, linkdown, linkup)
    
    # cable diagnostics
    def cable_diag(self):
        # command
        command_regex = commands.cable_diag(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")

        # save output and test different patterns
        temp = self._session.before.decode("utf-8")
        match = re.search(command_regex["regex"], temp)
        
        # if it's patterns with pairs' lengths, return list
        if match.group(1):
            return re.findall(command_regex["findall"], temp)
        # if it's just a diagnose, return string
        return match.group(11)
    
    # check log if port is flapping
    def get_log_port_flapping(self):
        # clipaging is necessary to check limited log output
        self._session.sendline(self._turn_clipaging["enable"])
        self._session.expect("#")
        
        # command, expect log's continuation or end
        command_regex = commands.show_log(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        index = self._session.expect(["CTRL", "#"])
        
        # save and parse log
        log = self._session.before.decode("utf-8")
        match = re.search(command_regex["login_and_first"], log)
        
        # try to parse datetime while scrolling log
        try:
            # find login and the earliest displayed time, for 3028, datetime consists of date and time
            if self._model == "DES-3028" or self._model == "DGS-3120-24TC" or self._model == "DGS-3000-24TC" or self._model == "DGS-3200-24" or self._model == "DES-3200-28" or self._model == "DES-3526":
                login_datetime = datetime.strptime(match.group(1) + " " + match.group(2), command_regex["format"])
                first_datetime = datetime.strptime(match.group(3) + " " + match.group(4), command_regex["format"])
            # for 1210, datetime consists of month, day and day, year is current year
            elif self._model == "DGS-1210-28/ME":
                login_datetime = datetime.strptime(str(datetime.now().year) + " " + " ".join(match.group(1, 2, 3)), command_regex["format"])
                first_datetime = datetime.strptime(str(datetime.now().year) + " " + " ".join(match.group(4, 5, 6)), command_regex["format"])
                # when new year comes
                if first_datetime.month > login_datetime.month:
                    first_datetime = first_datetime.replace(year=first_datetime.year - 1)
            
            # find the difference between login time and the earliest displayed time
            range_minutes_difference = int((login_datetime - first_datetime).total_seconds() // 60)
            
            # scroll until end found or range max time difference reached
            while index == 0 and range_minutes_difference < Const.max_minute_range_port_flapping.value:
                # command to scroll, decide is it continuation or end
                self._session.send(" ")
                index = self._session.expect(["CTRL", "#"])
                
                # parse current log output
                current_log = self._session.before.decode("utf-8")
                match = re.search(command_regex["first"], current_log)
                
                # if no datetime found while new page scanning, it means new page is empty
                if not match:
                    break
                
                # find the earliest displayed time, for 3028
                if self._model == "DES-3028" or self._model == "DGS-3120-24TC" or self._model == "DGS-3000-24TC" or self._model == "DGS-3200-24" or self._model == "DES-3200-28" or self._model == "DES-3526":
                    first_datetime = datetime.strptime(match.group(1) + " " + match.group(2), command_regex["format"])
                # for 1210, also check year's switching
                elif self._model == "DGS-1210-28/ME":
                    first_datetime = datetime.strptime(str(datetime.now().year) + " " + " ".join(match.group(1, 2, 3)), command_regex["format"])
                    if first_datetime.month > login_datetime.month:
                        first_datetime = first_datetime.replace(year=first_datetime.year - 1)
                
                # update range time difference
                range_minutes_difference = int((login_datetime - first_datetime).total_seconds() // 60)
                
                # update log variable
                log += current_log
        
        # if datetime on switch is couldn't be parsed, quit log and raise new exception
        except ValueError:
            self._session.send("q")
            self._session.expect("#")
            raise ValueError
        
        # if still log continuation, quit
        if index == 0:
            self._session.send("q")
            self._session.expect("#")
        
        # get back to disabled clipaging
        self._session.sendline(self._turn_clipaging["disable"])
        self._session.expect("#")
        
        # try to find last port flapping, return 0 if not found
        match = re.search(command_regex["regex"], log)
        if not match:
            return 0, 0
        
        # find last port flap, for 3028
        if self._model == "DES-3028" or self._model == "DGS-3120-24TC" or self._model == "DGS-3000-24TC" or self._model == "DGS-3200-24" or self._model == "DES-3200-28" or self._model == "DES-3526":
            last_flap_datetime = datetime.strptime(match.group(1) + " " + match.group(2), command_regex["format"])
        # for 1210
        elif self._model == "DGS-1210-28/ME":
            last_flap_datetime = datetime.strptime(str(datetime.now().year) + " " + " ".join(match.group(1, 2, 3)), command_regex["format"])
        
        # find the difference between login time and last port flapping time
        last_flap_login_minutes_difference = int((login_datetime - last_flap_datetime).total_seconds() // 60)
        
        # find the count of port flapping and return it with the time difference
        count_port_flapping = len(re.findall(command_regex["findall"], log))
        return count_port_flapping, last_flap_login_minutes_difference
    
    # get mac addresses on port
    def get_fdb_port(self):
        # command
        command_regex = commands.show_fdb(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # get rows as "vid vlan mac type" and return set of macs
        matches = re.findall(command_regex["regex"], self._session.before.decode("utf-8"))
        return {i[2] for i in matches}
    
    # get port security state on port
    def get_port_security(self):
        # command
        command_regex = commands.show_port_security(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect(command_regex["regex"])
        
        # return state of port security
        return self._session.match.group(1).decode("utf-8") == "Enabled"
    
    # get crc errors on port
    def get_crc_errors_port(self):
        # command
        command_regex = commands.show_crc_errors(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect(command_regex["regex"])
        
        # save match and quit dynamic page on some switches
        match = self._session.match
        if self._model == "DGS-3200-24" or self._model == "DES-3200-28":
            self._session.send("q")
            self._session.expect("#")
        
        # return rx crc errors' count
        return int(match.group(1).decode("utf-8"))
    
    # get packages bytes on port
    def get_packets_port(self):
        # command
        command_regex = commands.show_packet(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect(command_regex["regex"])
        
        # save match and quit dynamic page on some switches
        match = self._session.match
        if self._model == "DGS-3200-24" or self._model == "DES-3200-28":
            self._session.send("q")
            self._session.expect("#")
        
        # return rx and tx bytes as integers, period in seconds also (default 1 sec)
        return map(lambda x: int(x.decode("utf-8")) if x else 1, match.group(1, 2, 3))

    # get all vlans on switch
    def get_switch_vlans(self):
        # command
        command_regex = commands.show_vlan(self._model)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # get vlan_id: vlan_name
        return {int(vlan_id): vlan_name for vlan_id, vlan_name in re.findall(command_regex["regex"], self._session.before.decode("utf-8"))}
    
    # get vlans on port
    def get_port_vlans(self):
        # command
        command_regex = commands.show_vlan_ports(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # dictionary for vlans with statuses as keys
        port_vlans = defaultdict(list)
        
        # parse entry, X means actual status
        for match in re.finditer(command_regex["regex"], self._session.before.decode("utf-8")):
            if int(match[1]) != Const.iptv_vlan_skipping.value:   # skip old iptv vlan
                port_vlans[next(key for key, val in match.groupdict().items() if val == "X")].append(int(match[1]))
        
        # return completed dictionary
        return port_vlans
    
    # get acl options on port from overall output
    def get_port_acl(self):
        # command
        command_regex = commands.show_access_profile(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # return found entries
        if self._model == "DES-3028":
            # for 3028 two indentical entries
            return re.findall(command_regex["regex"], self._session.before.decode("utf-8"))
        elif self._model == "DES-3200-28":
            # for 3200-28 two identical entries constructed from parts
            return [l + r for l, r in re.findall(command_regex["regex"], self._session.before.decode("utf-8"))]
        elif self._model == "DGS-1210-28/ME" or self._model == "DGS-3120-24TC" or self._model == "DGS-3000-24TC" or self._model == "DGS-3200-24" or self._model == "DES-3526":
            # for 1210 two different entries for different protocols, one separated in parts
            match = re.search(command_regex["regex"], self._session.before.decode("utf-8"))
            return [match.group(1) + match.group(2), match.group(3)] if match else []
    
    # get default gateway for this switch, used for direct public ip
    def get_default_gateway(self):
        # command
        command_regex = commands.show_default_gateway(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        
        # return default gateway field from switch configuration
        self._session.expect(command_regex["regex"])
        return self._session.match.group(1).decode("utf-8")


##### CLASS TO COMMUNICATE WITH L3 GATEWAY #####

class L3Manager(NetworkManager):
    # L3 manager inits by user ip and base constructor
    def __init__(self, ipaddress, user_ip):
        super().__init__(ipaddress)
        self.__user_ip = user_ip
    
    # find ip route for direct public ip
    def check_ip_route(self):
        # get regex
        command_regex = commands.show_ip_route(self._model, self.__user_ip)
        
        # for cisco-like cli, dynamically try to find ip route in overall output
        if self._model == "DGS-3630-28SC":
            # clipaging is necessary to check limited ip route output
            self._session.sendline(self._turn_clipaging["enable"])
            self._session.expect("#")
            
            # command, expect ip route's continuation or end
            self._session.sendline(command_regex["command"])
            index = self._session.expect(["CTRL", "#"])
            
            # parse output without saving as all rows are separated
            match = re.search(command_regex["regex"], self._session.before.decode("utf-8"))
            
            # scroll until end found or range max time difference reached
            while index == 0 and not match:
                # command to scroll, decide is it continuation or end
                self._session.send(" ")
                index = self._session.expect(["CTRL", "#"])
                
                # parse current output
                match = re.search(command_regex["regex"], self._session.before.decode("utf-8"))
            
            # if still output continuation, quit
            if index == 0:
                self._session.send("q")
                self._session.expect("#")
            
            # get back to disabled clipaging
            self._session.sendline(self._turn_clipaging["disable"])
            self._session.expect("#")
        
        # for d-link cli, show and parse exact ip route record
        else:   # if self._model == "DGS-3620-28SC":
            # command
            self._session.sendline(command_regex["command"])
            self._session.expect("#")
            
            # parsing
            match = re.search(command_regex["regex"], self._session.before.decode("utf-8"))
        
        # return next hop ip for this ip route
        return match.group(1) if match else None
    
    # check arp by ip and return mac address
    def check_arpentry_ip_return_mac(self):
        # command
        command_regex = commands.show_arp_ip(self._model, self.__user_ip)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # parse and find mac address for this ip
        match = re.search(command_regex["regex"], self._session.before.decode("utf-8"))
        
        # if there's arp, return mac
        if match:
            return match.group("mac")
        return None
    
    # check arp by mac address and return list of ip addresses
    def check_arpentry_mac_return_ips(self, mac):
        # command
        command_regex = commands.show_arp_mac(self._model, mac)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # parse and find all ip addresses for this mac
        matches = re.finditer(command_regex["regex"], self._session.before.decode("utf-8"))
        
        # if found, return list of ip addresses
        if matches:
            return [match.group("ip") for match in matches]
        return None
    
    # check if mac address is visible on L3
    def check_mac_on_L3(self, mac):
        # command
        command_regex = commands.show_fdb_L3(self._model, mac)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # return True if error when trying to find mac address
        match = re.search(command_regex["regex"], self._session.before.decode("utf-8"))
        return not match


##### MAIN CLASS TO HANDLE ALL WORK #####

class MainHandler:
    def __init__(self, usernum):
        # init by usernum, declare fields for main objects
        self.__usernum = usernum
        self.__db_manager = None
        self.__switch_manager = None
        self.__gateway_manager = None
        
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
        self.__double_port = []   # there will be usernums if found doubles
        self.__double_ip = []
        
        # flags and variables for diagnostics of L2 and L3
        self.__switch_vlans = {}
        self.__have_vlan404 = False
        self.__untagged_vlan_id = 0
        self.__port_vlans = {}   # VID: status
        self.__fiber_port = False
        self.__mac_addresses = {}
        self.__port_security = False
        self.__need_to_cable_diag = False   # if necessary to cable diag later
        self.__crc_errors = 0
        self.__rx_bytes = 0
        self.__tx_bytes = 0
        self.__rx_megabit = 0
        self.__tx_megabit = 0
        self.__have_arp = False
        
        # flags for errors in diagnostics of L2
        self.__no_vlan = False
        self.__user_vlan_instead_of_vlan404 = False
        self.__vlan404_instead_of_user_vlan = False
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
        self.__no_arp = False
        self.__arp_on_unknown_mac = ""   # here wiil be unknown mac if found
        self.__ip_incorrect_arp_on_mac = []    # here will be unknown ip addresses if found
        self.__need_to_check_mac_on_L3 = False
        self.__no_mac_on_L3 = False
    
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
        return 0
    
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
                    # check for double port
                    self.__double_port = self.__check_double_switch_port()
            
            # check for double ip
            if self.__correctly_filled["ip"] == 1:
                self.__double_ip = self.__check_double_ip()
            
            # check mask and subnet
            if self.__correctly_filled["mask"] == 1:
                mask_length = self.__get_mask_length()
                # set a special flag if mask's address doesn't suit to regular mask
                if not mask_length:
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
    
    # check if port in user's card belongs to switch's portlist
    def __check_port_in_switch_portlist(self):
        return self.__switch_manager.check_port_in_portlist()
    
    # check port and mark flags
    def __check_port(self):
        # check port, get its type, settings and status, linkdown_status is actual if port is enabled
        self.__fiber_port, self.__port_disabled, self.__speed_settings, self.__linkdown_status, speed = self.__switch_manager.get_port_link()
        
        # check if speed is satisfying, cable diag needed if not
        if not self.__port_disabled and not self.__linkdown_status and not (speed == Const.normal_speed.value[True] or not self.__gigabit and speed == Const.normal_speed.value[False]):
            self.__lower_speed = speed
            self.__need_to_cable_diag = True
    
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
        if last_flap_remoteness < Const.last_flap_max_minute_remoteness.value and count_flapping >= Const.min_count_flapping.value:
            self.__port_flapping = True
            self.__need_to_cable_diag = True
    
    # check mac addresses and get as a set
    def __check_mac(self):
        # get set of all mac addresses
        self.__mac_addresses = self.__switch_manager.get_fdb_port()
        
        # error when there's no mac, cable diag needed
        if not self.__mac_addresses:
            self.__no_mac = True
            self.__need_to_cable_diag = True
        # error when there're more than 1 mac
        elif len(self.__mac_addresses) > 1:
            self.__many_macs = len(self.__mac_addresses)
        
        # check if port security is enabled
        self.__port_security = self.__switch_manager.get_port_security()
    
    # check crc errors
    def __check_crc(self):
        # get numbers of rx crc errors, will be zero if OK
        self.__crc_errors = self.__switch_manager.get_crc_errors_port()
    
    # calculate megabit from bytes, bytes number may be in the period of 1 or 5 seconds
    def __byte_to_megabit(self, bytes_count, seconds):
        return round(bytes_count * 8 / 1024 / 1024 / seconds)
    
    # check packet bytes and calculate megabit
    def __check_packets(self):
        # get rx and tx bytes
        seconds, self.__rx_bytes, self.__tx_bytes = self.__switch_manager.get_packets_port()
        
        # calculate to megabit
        self.__rx_megabit = self.__byte_to_megabit(self.__rx_bytes, seconds)
        self.__tx_megabit = self.__byte_to_megabit(self.__tx_bytes, seconds)
    
    # check vlans on switch and on port10.146.0.252

    def __check_vlan(self):
        # get switch vlans
        self.__switch_vlans = self.__switch_manager.get_switch_vlans()
        self.__have_vlan404 = Const.vlan404.value in self.__switch_vlans
        
        # get port vlans
        self.__port_vlans = self.__switch_manager.get_port_vlans()
        
        # no_vlan flag if port has no vlans of any status
        if not self.__port_vlans:
            self.__no_vlan = True
        
        # check if there's only 1 untagged vlan, remember it
        elif Const.vlan_statuses.value[0] in self.__port_vlans and len(self.__port_vlans[Const.vlan_statuses.value[0]]) == 1:
            self.__untagged_vlan_id = self.__port_vlans[Const.vlan_statuses.value[0]][0]
            
            # mark flag if port doesn't have vlan404 when it's on switch
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
        hex_entries = self.__switch_manager.get_port_acl()
        
        # if there's less than needed entries
        if len(hex_entries) < 2:
            self.__no_acl = True
        # if at least one entry doesn't match ip
        elif any([self.__get_ip_from_acl(i) != self.__record_data["ip"] for i in hex_entries]):
            self.__wrong_acl = True
    
    # check for direct public ip and find its gateway where arp should be
    def __find_actual_gateway(self):
        # init L3 manager by user record's gateway if ip is local
        if not self.__direct_public_ip:
            self.__gateway_manager = L3Manager(self.__record_data["gateway"], self.__record_data["ip"])
            return
        
        # on Lensoveta 23, define gateway address for direct public ip
        if self.__record_data["street"] == Const.lensoveta_address_gateway.value["street"] and self.__record_data["house"] == Const.lensoveta_address_gateway.value["house"]:
            self.__gateway_manager = L3Manager(Const.lensoveta_address_gateway.value["gateway"], self.__record_data["ip"])
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
            # break if self-route found or continue with new L3 manager if new next hop found
            elif gateway == self.__record_data["ip"]:
                return
    
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
            self.__have_arp = True
            
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
    
    # function to control diagnosting L2 and L3
    def __check_L2_L3(self):
        try:
            if not self.__switch_port:   # exception if there's no data
                raise Exception("Unable to diagnose L2: don't have switch and port")
            
            # connect to switch only if switch and port are known
            self.__switch_manager = L2Manager(self.__record_data["switch"], self.__record_data["port"])
            
            # exception if port is outside switch's portlist
            if not self.__check_port_in_switch_portlist():
                raise Exception("Unable to diagnose L2: user's port is outside switch's portlist")
            
            # if subnet is correct, check vlan and acl
            if self.__ip_mask_gateway:
                # check vlan
                self.__check_vlan()
                
                # check acl
                self.__check_acl()
            
            # check port
            self.__check_port()
            
            # if link is down not because of disabled port, try cable diag
            if self.__linkdown_status:
                self.__try_cable_diag()
            # in other case, diagnose further options
            else:
                # check log for flapping
                self.__check_log()
                
                # check mac
                self.__check_mac()
                
                # check crc errors
                self.__check_crc()
                
                # check packets
                self.__check_packets()
                
                # if speed isn't relevant, port is flapping or there's no mac, try cable_diag afterall
                if self.__need_to_cable_diag:
                    self.__try_cable_diag()
            
            # if subnet isn't correct, quit and send a message
            if not self.__ip_mask_gateway:
                raise Exception("Unable to diagnose ACL, VLAN and ARP: don't have correct subnet")
            
            # create L3 manager and check arpentry
            self.__find_actual_gateway()
            self.__check_arpentry_by_ip()
        
        finally:
            # always close connection and delete L2 and L3 managers
            if self.__switch_manager:
                del self.__switch_manager
            if self.__gateway_manager:
                del self.__gateway_manager
        
        """except Exception as err:
            if re.match("Unable to diagnose", str(err)):   # unable exception
                print(err)
            else:   # exception while working with L2 or L3
                print("Exception while working with equipment:", err, sep="\n")"""
    
    # result of L2 and L3 diagnostics
    def __result_L2_L3(self):
        # if there's no at least switch and port, terminate
        if not self.__switch_port:
            print("Не хватает данных для диагностики")
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
        elif self.__lower_speed:
            print("Линк", self.__lower_speed, "вместо", Const.normal_speed.value[self.__gigabit])
        else:
            print("Линк ок")
        
        # if port is or was flapping
        if self.__invalid_log_time:
            print("Сбились настройки времени на L2")
        elif self.__port_flapping:
            print("Линк скачет")
        
        # crc errors: count
        if self.__crc_errors:
            print("Ошибки CRC:", self.__crc_errors)
        else:
            print("Ошибки CRC: ок")
        
        # if linkup, show mac and packets
        if not self.__linkdown_status:
            # mac address: no mac, many macs
            if self.__no_mac:
                print("Нет мака на порту")
            elif self.__many_macs:
                print("Маков на порту:", self.__many_macs)
            else:
                print("Мак ок")
            
            # port security if enabled, makes sense when linkup
            if self.__port_security:
                print("Включён port_security")
            
            # packets: rx and tx bytes and megabit
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
        
        # vlan: no vlan, wrong tags, wrong untagged vlan
        vlan_error = False
        if self.__no_vlan:
            print("Нет влана на порту")
        for ind, status in enumerate(Const.vlan_statuses.value):
            if status in self.__port_vlans and (ind != 0 or not self.__untagged_vlan_id):
                vlan_error = True
                print("Влан", ", ".join(map(str, self.__port_vlans[status])), "в", status)
        if self.__untagged_vlan_id:
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
        
        # ip route: if not found
        if self.__ip_route_not_found:
            print("Не найден маршрут для прямого внешнего IP на L3")
        # arp: no arp, arp on unknown mac, correct
        if self.__no_arp:
            print("ARP не найдена")
        elif self.__arp_on_unknown_mac:
            print("ARP найдена на неизвестный мак:", self.__arp_on_unknown_mac)
        elif self.__have_arp:
            print("ARP ок")
        # if found arp by mac with wrong ip addresses, is possible even if arp ok or unknown mac
        if self.__ip_incorrect_arp_on_mac:
            print("По маку на порту найдена неверная ARP:", ", ".join(self.__ip_incorrect_arp_on_mac))
        # if mac was checked, print found or not
        if self.__need_to_check_mac_on_L3:
            if self.__no_mac_on_L3:
                print("Мак не виден на L3")
            else:
                print("Мак виден на L3")
    
    # main function
    def check_all(self):
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
        print(f"{Const.usernum.name}:{' '*(12-len(Const.usernum.name))}{self.__usernum}")
        for key in self.__record_data:
            print(f"{key}:{' '*(12-len(key))}{self.__record_data[key]}")
        
        print("-" * 20)


##### START DIAGNOSTICS #####

def main():
    # find .env file
    load_dotenv(find_dotenv())
    
    # get usernum
    usernum = int(input("Usernum: "))
    
    # create handler object and run diagnostics
    handler = MainHandler(usernum)
    handler.check_all()

if __name__ == "__main__":
    main()
