#!/usr/bin/python3
import re
# user's modules
from network_manager import NetworkManager
import commands


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
        # by default trying to find strict ip route by ip
        subnet_route = False
        
        # for cisco-like cli, dynamically try to find ip route in overall output
        if self._model == commands.cisco_switch:
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
        else:
            # command
            self._session.sendline(command_regex["command"])
            self._session.expect("#")
            
            # parsing
            match = re.search(command_regex["regex"], self._session.before.decode("utf-8"))
            
            # if strict ip route not found, try to find subnet route
            if not match:
                subnet_route = True
                match = re.search(command_regex["subnet_regex"], self._session.before.decode("utf-8"))
        
        # return flag to indicate trying to find subnet route and next hop
        return subnet_route, match
    
    # check ip interface's subnet by vlan matches user's gateway and mask length
    def check_ip_interface_subnet(self, vlanid_vlan, gateway, mask_length, public_name):
        # inner function to check if any of found subnets matches defined subnet
        def compare_subnet(gateways_masks):
            return any(g == gateway and int(m) == mask_length for g, m in gateways_masks)
        
        # on d-link, turn on clipaging because it can bug for a second
        if self._model != commands.cisco_switch:
            self._session.sendline(self._turn_clipaging["enable"])
            self._session.expect("#")

        # command, public_name is used for ipif for direct public ip
        command_regex = commands.show_ip_interface(self._model, vlanid_vlan, public_name)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # find one or several subnets
        match = re.findall(command_regex["regex"], self._session.before.decode("utf-8"))

        # on d-link, get back to disabled clipaging
        if self._model != commands.cisco_switch:
            self._session.sendline(self._turn_clipaging["disable"])
            self._session.expect("#")
        
        # return -1 if ipif not found or result of comparing subnets
        if not match:
            return -1
        return compare_subnet(match)
    
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