#!/usr/bin/python3
import re
from collections import defaultdict
from datetime import datetime
# user's modules
from base_switch import BaseSwitch
from const import Provider, CitySwitch
import commands


##### CLASS TO COMMUNICATE WITH L2 SWITCH #####

class L2Switch(BaseSwitch):
    __ports: int
    __user_port: str

    # L2 manager inits by user's port and base constructor
    def __init__(self, ipaddress: str, user_port: int, print_output: bool = False) -> None:
        super().__init__(ipaddress, "L2 switch", print_output)

        # user's port
        self.__user_port = user_port

        # remember number of ports for this switch and then save base model for further diagnosing
        self.__ports = commands.SWITCHES[self._model]["ports"]
        self._model = commands.SWITCHES[self._model]["base_switch"]
    
    # return True is user's port is inside switch's portlist
    def check_port_in_portlist(self) -> bool:
        return self.__user_port <= self.__ports
    
    # handler to check and return info about port
    def get_port_link(self) -> tuple[bool, bool, str | None, str | None, str | None]:
        # get all important parts including port type
        fiber, state, settings, linkdown, linkup = self.__show_port()

        # check if it's fiber port on 1210
        if self.__check_last_fiber_port():
            fiber = True
        
        # modify to useful form
        state = state.decode("utf-8") == "Disabled"   # boolean
        settings = None if settings.decode("utf-8") == "Auto" else settings.decode("utf-8")   # if resctricted
        linkdown = linkdown.decode("utf-8") if linkdown and not state else None   # if down with enabled port
        linkup = linkup.decode("utf-8") if linkup else None   # speed if up
        
        # return all modified
        return fiber, state, settings, linkdown, linkup
    
    # show ports and catch groups
    def __show_port(self) -> tuple[bool, str, str, str, str]:
        # command
        command_regex = commands.show_ports(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        
        # try expressions for simple and combo ports
        index = self._session.expect(command_regex["regex"])
        
        # save match and quit dynamic page on some switches
        match = self._session.match
        if self._model in {"DGS-3200-24", "DES-3200-28"}:
            self._quit_output()
        
        # if it's combo port and active type is fiber
        if index == 1 and match.group(10):
            return True, *match.group(6, 7, 9, 10)
        # otherwise
        return False, *match.group(1, 2, 4, 5)
    
    # check if user's port is one of last 4 fiber ports on 1210-28 or 1210-52
    def __check_last_fiber_port(self):
        return self._model == "DGS-1210-28/ME" and self.__ports - self.__user_port < 4

    # cable diagnostics
    def cable_diag(self) -> list[tuple[int, str] | tuple[int, str, int]] | str:
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
    def get_log_port_flapping(self) -> tuple[int, int]:
        # clipaging is necessary to check limited log output
        self._turn_on_clipaging()
        
        # command, expect log's continuation or end
        command_regex = commands.show_log(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        index = self._session.expect(["CTRL", "#"])
        
        # save and parse log
        log = self._session.before.decode("utf-8")
        match = re.search(command_regex["login_and_first"], log)
        
        # try to parse datetime while scrolling log
        try:
            # find login and the earliest displayed time, for 1210, datetime consists of month, day and day, year is current year
            if self._model == "DGS-1210-28/ME":
                login_datetime = datetime.strptime(str(datetime.now().year) + " " + " ".join(match.group(1, 2, 3)), command_regex["format"])
                first_datetime = datetime.strptime(str(datetime.now().year) + " " + " ".join(match.group(4, 5, 6)), command_regex["format"])
                # when new year comes
                if first_datetime.month > login_datetime.month:
                    first_datetime = first_datetime.replace(year=first_datetime.year - 1)
            # for other, datetime consists of date and time
            else:
                login_datetime = datetime.strptime(match.group(1) + " " + match.group(2), command_regex["format"])
                first_datetime = datetime.strptime(match.group(3) + " " + match.group(4), command_regex["format"])
            
            # find the difference between login time and the earliest displayed time
            range_minutes_difference = int((login_datetime - first_datetime).total_seconds() // 60)
            
            # scroll until end found or range max time difference reached
            while index == 0 and range_minutes_difference < CitySwitch.MAX_MINUTE_RANGE_PORT_FLAPPING:
                # command to scroll, decide is it continuation or end
                self._session.send(" ")
                index = self._session.expect(["CTRL", "#"])
                
                # parse current log output
                current_log = self._session.before.decode("utf-8")
                match = re.search(command_regex["first"], current_log)
                
                # if no datetime found while new page scanning, it means new page is empty
                if not match:
                    break
                
                # find the earliest displayed time, for 1210, also check year's switching
                if self._model == "DGS-1210-28/ME":
                    first_datetime = datetime.strptime(str(datetime.now().year) + " " + " ".join(match.group(1, 2, 3)), command_regex["format"])
                    if first_datetime.month > login_datetime.month:
                        first_datetime = first_datetime.replace(year=first_datetime.year - 1)
                # for other
                else:
                    first_datetime = datetime.strptime(match.group(1) + " " + match.group(2), command_regex["format"])
                
                # update range time difference
                range_minutes_difference = int((login_datetime - first_datetime).total_seconds() // 60)
                
                # update log variable
                log += current_log
        
        # if datetime on switch is couldn't be parsed
        except ValueError:
            # quit log and disable clipaging back
            self._quit_output()
            self._turn_off_clipaging()
            
            # throw exception again
            raise
        
        # if still log continuation, quit
        if index == 0:
            self._quit_output()
        
        # get back to disabled clipaging
        self._turn_off_clipaging()
        
        # try to find last port flapping, return 0 if not found
        match = re.search(command_regex["regex"], log)
        if not match:
            return 0, 0
        
        # find last port flap, for 1210
        if self._model == "DGS-1210-28/ME":
            last_flap_datetime = datetime.strptime(str(datetime.now().year) + " " + " ".join(match.group(1, 2, 3)), command_regex["format"])
        # for other
        else:
            last_flap_datetime = datetime.strptime(match.group(1) + " " + match.group(2), command_regex["format"])
        
        # find the difference between login time and last port flapping time
        last_flap_login_minutes_difference = int((login_datetime - last_flap_datetime).total_seconds() // 60)
        
        # find the count of port flapping and return it with the time difference
        count_port_flapping = len(re.findall(command_regex["findall"], log))
        return count_port_flapping, last_flap_login_minutes_difference
    
    # get mac addresses on port, method is used for L2Protocol
    def get_mac_addresses(self) -> set[str]:
        # command
        command_regex = commands.show_fdb(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # get rows as "vid vlan mac type" and return set of macs
        matches = re.findall(command_regex["regex"], self._session.before.decode("utf-8"))
        return {i[2] for i in matches}
    
    # get port security state on port
    def get_port_security(self) -> bool:
        # command
        command_regex = commands.show_port_security(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect(command_regex["regex"])
        
        # return state of port security
        return self._session.match.group(1).decode("utf-8") == "Enabled"
    
    # get crc errors on port
    def get_crc_errors_port(self) -> int:
        # command
        command_regex = commands.show_crc_errors(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect(command_regex["regex"])
        
        # save match and quit dynamic page on some switches
        match = self._session.match
        if self._model in {"DGS-3200-24", "DES-3200-28"}:
            self._quit_output()
        
        # return rx crc errors' count
        return int(match.group(1).decode("utf-8"))
    
    # get packages bytes on port
    def get_packets_port(self) -> tuple[int]:
        # command
        command_regex = commands.show_packet(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect(command_regex["regex"])
        
        # save match and quit dynamic page on some switches
        match = self._session.match
        if self._model in {"DGS-3200-24", "DES-3200-28"}:
            self._quit_output()
        
        # return rx and tx bytes as integers
        return tuple(map(int, match.group(2, 3)))

    # get all vlans on switch
    def get_switch_vlans(self) -> dict[int, str]:
        # command
        command_regex = commands.show_vlan(self._model)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # get vlan_id: vlan_name
        return {int(vlan_id): vlan_name for vlan_id, vlan_name in re.findall(command_regex["regex"], self._session.before.decode("utf-8"))}
    
    # get vlans on port
    def get_port_vlans(self) -> dict[str, list[int]]:
        # command
        command_regex = commands.show_vlan_ports(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")
        
        # dictionary for vlans with statuses as keys
        port_vlans = defaultdict(list)
        
        # parse entry, X means actual status
        for match in re.finditer(command_regex["regex"], self._session.before.decode("utf-8")):
            if int(match[1]) not in Provider.VLAN_SKIPPING:   # skip old iptv vlan
                port_vlans[next(key for key, val in match.groupdict().items() if val == "X")].append(int(match[1]))
        
        # return completed dictionary
        return port_vlans
    
    # get dhcp servers and vlan ids from switch's dhcp relay
    def get_dhcp_relay(self) -> tuple[None, None] | tuple[tuple[str], int] | tuple[tuple[str], list[str]]:
        # command
        command_regex = commands.show_dhcp_relay(self._model)
        self._session.sendline(command_regex["command"])
        self._session.expect("#")

        # find dhcp servers' addresses
        temp = self._session.before.decode("utf-8")
        match_servers = re.search(command_regex["servers"], temp)
        
        # if no servers found
        if not match_servers:
            return None, None
        
        # for 1210, get vlan ids from vid list
        if self._model == "DGS-1210-28/ME":
            match_vlan_ids = re.search(command_regex["regex"], temp)
            return match_servers.group("dhcp_server1", "dhcp_server2"), [i.strip() for i in match_vlan_ids.group("vlan_ids_list").split(",")]
        
        # for 3120 and 3000, check servers and list of vlan ids with servers
        elif self._model in ["DGS-3120-24TC", "DGS-3000-24TC"]:
            # get two strings with primary and secondary dhcp servers and their vlan ids lists
            servers_vlan_ids = re.search(command_regex["regex"], temp)
            # if not found, servers differs from previously found ones or vlan ids lists are different, return empty vlan ids list
            if (not servers_vlan_ids or servers_vlan_ids.group("dhcp_server1", "dhcp_server2") != match_servers.group("dhcp_server1", "dhcp_server2")
                    or servers_vlan_ids.group("vlan_ids_list1") != servers_vlan_ids.group("vlan_ids_list2")):
                return match_servers.group("dhcp_server1", "dhcp_server2"), [""]
            # otherwise return servers and vlan ids
            return match_servers.group("dhcp_server1", "dhcp_server2"), [i for i in servers_vlan_ids.group("vlan_ids_list1").split(",")]
        
        # return servers and -1 if this switch model doesn't have to have dhcp relay: ["DES-3028", "DES-3200-28", "DES-3526", "DGS-3200-24"]
        else:
            return match_servers.group("dhcp_server1", "dhcp_server2"), -1

    # get acl options on port from overall output
    def get_port_acl(self) -> list[str]:
        # clipaging is necessary because it's much faster on some models to scroll by space
        self._turn_on_clipaging()

        # command
        command_regex = commands.show_access_profile(self._model, self.__user_port)
        self._session.sendline(command_regex["command"])
        # for 1210, it's important to skip ## sequence and expect only one # symbol
        index = self._session.expect(["CTRL", r"(?<!#)#(?!#)"])

        # save output and try to find end of permit block
        acl = self._session.before.decode("utf-8")
        match = re.search("Deny", acl)
        
        # scroll until end reached or deny block started
        while index == 0 and not match:
            # command to scroll, decide is it continuation or end
            self._session.send(" ")
            # to skip ## sequence and expect only one # symbol
            index = self._session.expect(["CTRL", r"(?<!#)#(?!#)"])

            # try to find end of permit block and concatenate output
            match = re.search("Deny", self._session.before.decode("utf-8"))
            acl += self._session.before.decode("utf-8")

        # if still acl continuation, quit
        if index == 0:
            self._quit_output()
        
        # get back to disabled clipaging
        self._turn_off_clipaging()

        # clean ansi sequences
        acl = acl.replace("\x00", "")
        ansi_escape = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
        acl = ansi_escape.sub('', acl)

        # filter lines to get only useful ones
        filtered_lines = [
            line for line in acl.splitlines()   # splitlines accurately split with all space symbols
            if line.strip()   # if line is not empty
            and not re.search(r'\[[0-9;]*[mK]', line)   # if line is not some skipped ansi symbol 
            and not re.search(r'Quit|Next Page|Next Entry|ALL', line)   # if it's not hint line
        ]

        # collect filtered lines in one big text
        acl = "\n".join(filtered_lines).strip()

        # return found entries
        if self._model == "DES-3028":
            # for 3028 two indentical entries
            return re.findall(command_regex["regex"], acl)
        elif self._model == "DES-3200-28":
            # for 3200-28 two identical entries constructed from parts
            return [l + r for l, r in re.findall(command_regex["regex"], acl)]
        elif self._model in {"DGS-1210-28/ME", "DGS-3120-24TC", "DGS-3000-24TC", "DGS-3200-24", "DES-3526"}:
            # for other two different entries for different protocols, one separated in parts
            match = re.search(command_regex["regex"], acl)
            return [match.group(1) + match.group(2), match.group(3)] if match else []