#!/usr/bin/python3
import re

switches = {"DES-3028": {"base_switch": "DES-3028", "ports": 28},
                              "DES-3052": {"base_switch": "DES-3028", "ports": 52},
                              "DGS-1210-28/ME": {"base_switch": "DGS-1210-28/ME", "ports": 28},
                              "DGS-1210-52/ME": {"base_switch": "DGS-1210-28/ME", "ports": 52},
                              "DGS-3000-24TC": {"base_switch": "DGS-3000-24TC", "ports": 24},
                              "DGS-3000-26TC": {"base_switch": "DGS-3000-24TC", "ports": 24},
                              "DGS-3120-24TC": {"base_switch": "DGS-3120-24TC", "ports": 26},
                              "DGS-3200-24": {"base_switch": "DGS-3200-24", "ports": 26},
                              "DES-3200-28": {},
                              "DES-3526": {},
                              # L3
                              "DGS-3620-28TC": {},
                              "DGS-3620-28SC": {},
                              "DGS-3627G": {},
                              "DGS-3630-28SC": {}}

def clipaging(model):
    match model:
        case "DGS-3630-28SC":
            return {"disable": "terminal length 0",
                    "enable": "terminal length 24"}
        case _:
            return {"disable": "disable clipaging",
                    "enable": "enable clipaging"}

##### FOR L2 SWITCH #####

def show_ports(model, user_port):
    match model:
        case "DES-3028":
            return {"command": f"show ports {user_port}",
                    "regex": [rf"{user_port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#", rf"{user_port}\(C\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*{user_port}\(F\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#"]}
        case "DGS-1210-28/ME":
            return {"command": f"show ports {user_port}",
                    "regex": [rf"{user_port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+[ -]?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled).*#"]}
        case "DGS-3120-24TC":
            return {"command": f"show ports {user_port}",
                    "regex": [rf"(?:1:)?{user_port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#", rf"(?:1:)?{user_port}\s+\(C\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*(?:1:)?{user_port}\s+\(F\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#"]}
        case "DGS-3000-24TC":
            return {"command": f"show ports {user_port}",
                    "regex": [rf"{user_port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#", rf"{user_port}\s+\(C\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*{user_port}\s+\(F\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#"]}
        case "DGS-3200-24":
            return {"command": f"show ports {user_port}",
                    "regex": [rf"{user_port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*CTRL", rf"{user_port}\s+\(C\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*{user_port}\s+\(F\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*CTRL"]}

def cable_diag(model, user_port):
    match model:
        case "DES-3028":
            return {"command": f"cable_diag ports {user_port}",
                    "regex": rf"({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+Pair(\d)\s+([A-Za-z]+)\s+at\s+(\d+)\s+M\s+(-|\d+))|({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+([A-Za-z ]+)\s+(-|\d+))",
                    "findall": r"Pair(\d)\s+([A-Za-z]+)\s+at\s+(\d+)\s+M"}
        case "DGS-1210-28/ME":
            return {"command": f"cable diagnostic port {user_port}",
                    "regex": rf"({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+Pair(\d)\s+([A-Za-z]+)(?:\s+at\s+(\d+)\s+M)?\s+(-|\d+))|({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+([A-Za-z ]+)\s+(-|\d+))",
                    "findall": r"Pair(\d)\s+([A-Za-z]+)(?:\s+at\s+(\d+)\s+M)?"}
        case "DGS-3120-24TC":
            return {"command": f"cable_diag ports {user_port}",
                    "regex": rf"((?:1:)?{user_port}\s+(\S+)\s+(Link Up|Link Down)\s+Pair (\d)\s+([A-Za-z]+)(?:\s+at\s+(\d+)M)?\s+(-|\d+))|((?:1:)?{user_port}\s+(\S+)\s+(Link Up|Link Down)\s+([A-Za-z ]+)\s+(-|\d+))",
                    "findall": r"Pair (\d)\s+([A-Za-z]+)(?:\s+at\s+(\d+)M)?"}
        case "DGS-3000-24TC":
            return {"command": f"cable_diag ports {user_port}",
                    "regex": rf"({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+Pair (\d)\s+([A-Za-z]+)(?:\s+at\s+(\d+)M)?\s+(-|\d+))|({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+([A-Za-z ]+)\s+(-|\d+))",
                    "findall": r"Pair (\d)\s+([A-Za-z]+)(?:\s+at\s+(\d+)M)?"}
        case "DGS-3200-24":
            return {"command": f"cable_diag ports {user_port}",
                    "regex": rf"({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+Pair(\d)\s+([A-Za-z]+)(?:\s+at\s+(\d+)\s+M)?\s+(-|\d+))|({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+([A-Za-z ]+)\s+(-|\d+))",
                    "findall": r"Pair(\d)\s+([A-Za-z]+)(?:\s+at\s+(\d+)\s+M)?"}

def show_fdb(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DGS-3000-24TC" | "DGS-3200-24":
            return {"command": f"show fdb port {user_port}",
                    "regex": rf"(\d+)\s+(\S+)\s+(([A-Z\d]{{2}}-){{5}}[A-Z\d]{{2}})\s+{user_port}\s+([A-Za-z]+)"}
        case "DGS-3120-24TC":
            return {"command": f"show fdb port {user_port}",
                    "regex": rf"(\d+)\s+(\S+)\s+(([A-Z\d]{{2}}-){{5}}[A-Z\d]{{2}})\s+(?:1:)?{user_port}\s+([A-Za-z]+)"}

def show_port_security(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DGS-3200-24":
            return {"command": f"show port_security ports {user_port}",
                    "regex": rf"{user_port}\s+(Enabled|Disabled)\s+(\d+)\s+([A-Za-z]+).*#"}
        case "DGS-3120-24TC":
            return {"command": f"show port_security ports {user_port}",
                    "regex": rf"(?:1:)?{user_port}\s+(Enabled|Disabled)\s+([A-Za-z]+)\s+(\d+).*#"}
        case "DGS-3000-24TC":
            return {"command": f"show port_security ports {user_port}",
                    "regex": rf"{user_port}\s+(Enabled|Disabled)\s+([A-Za-z]+)\s+(\d+).*#"}

def show_crc_errors(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DGS-3000-24TC":
            return {"command": f"show error ports {user_port}",
                    "regex": r"RX Frames.*?CRC Error\s+(\d+).*#"}
        case "DGS-3120-24TC":
            return {"command": f"show error ports {user_port}",
                    "regex": r"RX Frames.*?CRC Error\s+(\d+).*#"}
        case "DGS-3200-24":
            return {"command": f"show error ports {user_port}",
                    "regex": r"RX Frames.*?CRC Error\s+(\d+).*CTRL"}

def show_packet(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DGS-3000-24TC":
            return {"command": f"show packet ports {user_port}",
                    "regex": r"Total/(\d)?sec.*RX Bytes\s+\d+\s+(\d+).*TX Bytes\s+\d+\s+(\d+).*#"}
        case "DGS-3120-24TC":
            return {"command": f"show packet ports {user_port}",
                    "regex": r"Total/(\d)?sec.*RX Bytes\s+\d+\s+(\d+).*TX Bytes\s+\d+\s+(\d+).*#"}
        case "DGS-3200-24":
            return {"command": f"show packet ports {user_port}",
                    "regex": r"Total/(\d)?sec.*RX Bytes\s+\d+\s+(\d+).*TX Bytes\s+\d+\s+(\d+).*CTRL"}

def show_vlan(model):
    match model:
        case "DES-3028" | "DGS-3120-24TC" | "DGS-3000-24TC" | "DGS-3200-24":
            return {"command": "show vlan",
                    "regex": r"VID\s+:\s+(\d+)\s+VLAN Name\s+:\s+(\S+)"}
        case "DGS-1210-28/ME":
            return {"command": "show vlan",
                    "regex": r"VID\s+:\s+(\d+)\s+VLAN NAME\s+:\s+(\S+)"}

def show_vlan_ports(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME":
            return {"command": f"show vlan ports {user_port}",
                    "regex": r"(\d+)\s+(?P<Untagged>[X-])\s+(?P<Tagged>[X-])\s+(?P<Forbidden>[X-])\s+(?P<Dynamic>[X-])"}
        case "DGS-3120-24TC" | "DGS-3000-24TC" | "DGS-3200-24":
            return {"command": f"show vlan ports {user_port}",
                    "regex": r"(\d+)\s+(?P<Untagged>[X-])\s+(?P<Tagged>[X-])\s+(?P<Dynamic>[X-])\s+(?P<Forbidden>[X-])"}

def show_default_gateway(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DGS-3120-24TC" | "DGS-3000-24TC" | "DGS-3200-24":
            return {"command": "show switch",
                    "regex": r"Default Gateway\s+:\s+((\d{1,3}.){3}\d{1,3}).*#"}

def show_access_profile(model, user_port):
    match model:
        case "DES-3028":
            return {"command": "show access_profile",
                    "regex": rf"Ports\s+:\s+{user_port}\s+Mode\s+:\s+Permit[\s\S]*?0x([a-z\d]{{8}})\s+0xffffffff"}
        case "DGS-1210-28/ME":
            return {"command": "show access_profile",
                    "regex": rf"Mode:\s+Permit\s+Time Range\s+:\s+Ports:\s+{user_port}\s+[\s\S]*?Filter Value = 0x0000([a-z\d]{{4}})\s+[\s\S]*?Filter Value = 0x([a-z\d]{{4}})0000\s+[\s\S]*?Mode:\s+Permit\s+Time Range\s+:\s+Ports:\s+{user_port}\s+[\s\S]*?Filter Value = 0x([a-z\d]{{8}})\s+"}
        case "DGS-3120-24TC":
            return {"command": "show access_profile",
                    "regex": rf"Ports:\s+(?:1:)?{user_port}\s+[\s\S]*?value : 0x0000([A-Z\d]{{4}})\s+[\s\S]*?value : 0x([A-Z\d]{{4}})0000\s+Mask : \S+\s+Action:\s+Permit[\s\S]*?Ports:\s+(?:1:)?{user_port}\s+[\s\S]*?value : 0x([A-Z\d]{{8}})\s+Mask : \S+\s+Action:\s+Permit"}
        case "DGS-3000-24TC" | "DGS-3200-24":
            return {"command": "show access_profile",
                    "regex": rf"Ports:\s+{user_port}\s+[\s\S]*?value : 0x0000([A-Z\d]{{4}})\s+[\s\S]*?value : 0x([A-Z\d]{{4}})0000\s+Mask : \S+\s+Action:\s+Permit[\s\S]*?Ports:\s+{user_port}\s+[\s\S]*?value : 0x([A-Z\d]{{8}})\s+Mask : \S+\s+Action:\s+Permit"}

def show_log(model, user_port):
    match model:
        case "DES-3028" | "DGS-3200-24":
            return {"command": "show log",
                    "format": "%Y-%m-%d %H:%M:%S",
                    "login_and_first": r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+Successful login[\s\S]*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})",
                    "first": r"[\s\S]*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})",
                    "regex": rf"(\d{{4}}-\d{{2}}-\d{{2}})\s+(\d{{2}}:\d{{2}}:\d{{2}})\s+Port {user_port}",
                    "findall": f"Port {user_port} link up"}
        case "DGS-1210-28/ME":
            return {"command": "show log",
                    "format": "%Y %b %d %H:%M:%S",
                    "login_and_first": r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\S+\s+Successful login[\s\S]*([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})",
                    "first": r"[\s\S]*([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})",
                    "regex": rf"([A-Za-z]{{3}})\s+(\d{{1,2}})\s+(\d{{2}}:\d{{2}}:\d{{2}})\S+\s+Port {user_port}",
                    "findall": f"Port {user_port} link up"}
        case "DGS-3120-24TC":
            return {"command": "show log",
                    "format": "%Y-%m-%d %H:%M:%S",
                    "login_and_first": r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+Successful login[\s\S]*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})",
                    "first": r"[\s\S]*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})",
                    "regex": rf"(\d{{4}}-\d{{2}}-\d{{2}})\s+(\d{{2}}:\d{{2}}:\d{{2}})\s+\S+\s+Port (?:1:)?{user_port}",
                    "findall": f"Port (?:1:)?{user_port} link up"}
        case "DGS-3000-24TC":
            return {"command": "show log",
                    "format": "%Y-%m-%d %H:%M:%S",
                    "login_and_first": r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+Successful login[\s\S]*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})",
                    "first": r"[\s\S]*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})",
                    "regex": rf"(\d{{4}}-\d{{2}}-\d{{2}})\s+(\d{{2}}:\d{{2}}:\d{{2}})\s+\S+\s+Port {user_port}",
                    "findall": f"Port {user_port} link up"}

##### FOR L3 GATEWAY #####

def show_ip_route(model, user_ip):
    match model:
        case "DGS-3630-28SC":
            return {"command": "show ip route static",
                    "regex": rf"{user_ip}/32\s+via\s+((\d{{1,3}}.){{3}}\d{{1,3}})(,\s+vlan(\d+))?"}
        case _:
            return {"command": f"show iproute {user_ip} static",
                    "regex": rf"{user_ip}/32\s+((\d{{1,3}}.){{3}}\d{{1,3}})"}

def show_arp_ip(model, user_ip):
    match model:
        case "DGS-3630-28SC":
            return {"command": f"show arp {user_ip}",
                    "regex": rf"{user_ip}\s+(?P<mac>([A-Z\d]{{2}}-){{5}}[A-Z\d]{{2}})\s+vlan(\d+)"}
        case _:
            return {"command": f"show arpentry ipaddress {user_ip}",
                    "regex": rf"(\S+)\s+{user_ip}\s+(?P<mac>([A-Z\d]{{2}}-){{5}}[A-Z\d]{{2}})"}

def show_arp_mac(model, user_mac):
    match model:
        case "DGS-3630-28SC":
            return {"command": f"show arp {user_mac}",
                    "regex": rf"(?P<ip>(\d{{1,3}}.){{3}}\d{{1,3}})\s+{user_mac}\s+vlan(\d+)"}
        case _:
            return {"command": f"show arpentry mac_address {user_mac}",
                    "regex": rf"(\S+)\s+(?P<ip>(\d{{1,3}}.){{3}}\d{{1,3}})\s+{user_mac}"}

def show_fdb_L3(model, user_mac):
    match model:
        case "DGS-3630-28SC":
            return {"command": f"show mac-address-table address {user_mac}",
                    "regex": rf"(\d+)\s+({user_mac})"}
        case _:
            return {"command": f"show fdb mac_address {user_mac}",
                    "regex": rf"(\d+)\s+(\S+)\s+({user_mac})"}

