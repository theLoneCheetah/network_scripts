#!/usr/bin/python3
import re

switches = {"DES-3028": {}, "DES-3052": {}, "DGS-1210-28/ME": {}, "DGS-1210-52/ME": {}, "DGS-3000-24TC": {}, "DGS-3000-26TC": {}, "DGS-3120-24TC": {}, "DGS-3200-24": {}, "DES-3200-28": {}, "DES-3526": {}, \
    "DGS-3620-28TC": {}, "DGS-3620-28SC": {}, "DGS-3627G": {}, "DGS-3630-28SC": {}}

# 3052 -> 3028

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
                    "regex": [rf"{user_port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled).*#", rf"{user_port}\(C\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled).*{user_port}\(F\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled).*#"]}

def cable_diag(model, user_port):
    match model:
        case "DES-3028":
            return {"command": f"cable_diag ports {user_port}",
                    "regex": rf"({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+Pair(\d)\s+([A-Za-z]+)\s+at\s+(\d+)\s+M\s+(-|\d+))|({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+([A-Za-z ]+)\s+(-|\d+))",
                    "findall": r"Pair(\d)\s+([A-Za-z]+)\s+at\s+(\d+)\s+M"}
        case "DGS-1210-28/ME":
            return {"command": f"cable diagnostic port {user_port}",
                    "regex": rf"({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+Pair(\d)\s+([A-Za-z]+)(\s+at\s+(\d+)\s+M)?\s+(-|\d+))|({user_port}\s+(\S+)\s+(Link Up|Link Down)\s+([A-Za-z ]+)\s+(-|\d+))",
                    "findall": r"Pair(\d)\s+([A-Za-z]+)(\s+at\s+(\d+)\s+M)?"}

def show_fdb(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME":
            return {"command": f"show fdb port {user_port}",
                    "regex": rf"(\d+)\s+(\S+)\s+(([A-Z\d]{{2}}-){{5}}[A-Z\d]{{2}})\s+{user_port}\s+([A-Za-z]+)"}

def show_port_security(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME":
            return {"command": f"show port_security ports {user_port}",
                    "regex": rf"{user_port}\s+(Enabled|Disabled)\s+(\d+)\s+([A-Za-z]+).*#"}

def show_crc_errors(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME":
            return {"command": f"show error ports {user_port}",
                    "regex": r"RX Frames.*?CRC Error\s+(\d+).*#"}

def show_packet(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME":
            return {"command": f"show packet ports {user_port}",
                    "regex": r"Total/(\d)?sec.*RX Bytes\s+\d+\s+(\d+).*TX Bytes\s+\d+\s+(\d+).*#"}

def show_vlan(model):
    match model:
        case "DES-3028":
            return {"command": "show vlan",
                    "regex": r"VID\s+:\s+(\d+)\s+VLAN Name\s+:\s+(\S+)"}
        case "DGS-1210-28/ME":
            return {"command": "show vlan",
                    "regex": r"VID\s+:\s+(\d+)\s+VLAN NAME\s+:\s+(\S+)"}

def show_vlan_ports(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME":
            return {"command": f"show vlan ports {user_port}",
                    "regex": r"(\d+)+\s+([X-])\s+([X-])\s+([X-])\s+([X-])"}

def show_switch(model, user_port):
    match model:
        case "DES-3028" | "DGS-1210-28/ME":
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

def show_log(model, user_port):
    match model:
        case "DES-3028":
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

##### FOR L3 GATEWAY #####

"""def (model, user_port):
    match model:
        case "DES-3028":
            return {"command": ,
                    "regex": }
        case "DGS-1210-28/ME":
            return {"command": ,
                    "regex": }"""

