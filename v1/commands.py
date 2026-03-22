#!/usr/bin/python3
from typing import TypeAlias, TypedDict

# alias for most of returned dictionaries
CommandRegexData: TypeAlias = dict[str, str]

# typeddist alias for show ports regex result
class ShowPortsCommandRegex(TypedDict):
    command: str
    regex: list[str]


##### SWITCH MODELS #####

# base_switches = {"DES-3028", "DES-3200-28", "DES-3526", "DGS-3000-24TC", "DGS-3200-24", "DGS-1210-28/ME", "DGS-3120-24TC"}

SWITCHES = {# L2
            "DES-3028": {"base_switch": "DES-3028", "ports": 28},
            "DES-3052": {"base_switch": "DES-3028", "ports": 52},
            "DES-3200-28": {"base_switch": "DES-3200-28", "ports": 28},
            "DES-3526": {"base_switch": "DES-3526", "ports": 26},
            "DGS-3000-24TC": {"base_switch": "DGS-3000-24TC", "ports": 24},
            "DGS-3000-26TC": {"base_switch": "DGS-3000-24TC", "ports": 24},
            "DGS-3200-24": {"base_switch": "DGS-3200-24", "ports": 24},
            "DGS-1210-28/ME": {"base_switch": "DGS-1210-28/ME", "ports": 28},
            "DGS-1210-52/ME": {"base_switch": "DGS-1210-28/ME", "ports": 52},
            # L2+
            "DGS-3120-24TC": {"base_switch": "DGS-3120-24TC", "ports": 24},
            # L3
            "DGS-3120-24SC": {},
            "DGS-3620-28TC": {},
            "DGS-3620-28SC": {},
            "DGS-3627G": {},
            "DGS-3630-28SC": {}}   # cisco-like
CISCO_SWITCH = "DGS-3630-28SC"


##### BASE COMMANDS #####

def show_model(cli_type: str) -> CommandRegexData:
    match cli_type:
        case "d-link":
            return {"command": "show switch",
                    "regex": r"Device Type\s+:\s+(?P<model>\S+)\s+.*Default Gateway\s+:\s+(?P<default_gateway>(\d{1,3}\.){3}\d{1,3})"}
        case "cisco":
            return {"command": "show version",
                    "regex": r"-+\s+1\s+(?P<model>\S+)\s+"}

def clipaging(model: str) -> CommandRegexData:
    match model:
        case x if x == CISCO_SWITCH:
            return {"disable": "terminal length 0",
                    "enable": "terminal length 24"}
        case _:
            return {"disable": "disable clipaging",
                    "enable": "enable clipaging"}


##### COMMANDS FOR L2 SWITCH #####

def show_ports(model: str, user_port: int) -> ShowPortsCommandRegex:
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
        case "DES-3200-28":
            return {"command": f"show ports {user_port}",
                    "regex": [rf"{user_port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*CTRL", rf"{user_port}\(C\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*{user_port}\(F\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*CTRL"]}
        case "DES-3526":
            return {"command": f"show ports {user_port}",
                    "regex": [rf"{user_port}\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#", rf"{user_port}\(C\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*{user_port}\(F\)\s+(Enabled|Disabled)\s+(Auto|10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/Disabled\s+(([A-Za-z]+ ?[A-Za-z]+)|(10{{1,3}}M\/Half|10{{1,3}}M\/Full)\/None).*#"]}

def cable_diag(model: str, user_port: int) -> CommandRegexData:
    match model:
        case "DES-3028" | "DES-3200-28" | "DES-3526":
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

def show_fdb(model: str, user_port: int) -> CommandRegexData:
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DGS-3000-24TC" | "DGS-3200-24" | "DES-3200-28" | "DES-3526":
            return {"command": f"show fdb port {user_port}",
                    "regex": rf"(\d+)\s+(\S+)\s+(([A-Z\d]{{2}}-){{5}}[A-Z\d]{{2}})\s+{user_port}\s+([A-Za-z]+)"}
        case "DGS-3120-24TC":
            return {"command": f"show fdb port {user_port}",
                    "regex": rf"(\d+)\s+(\S+)\s+(([A-Z\d]{{2}}-){{5}}[A-Z\d]{{2}})\s+(?:1:)?{user_port}\s+([A-Za-z]+)"}

def show_port_security(model: str, user_port: int) -> CommandRegexData:
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DGS-3200-24" | "DES-3200-28" | "DES-3526":
            return {"command": f"show port_security ports {user_port}",
                    "regex": rf"{user_port}\s+((?:E|e)nabled|(?:D|d)isabled)\s+(\d+)\s+([A-Za-z]+).*#"}
        case "DGS-3120-24TC":
            return {"command": f"show port_security ports {user_port}",
                    "regex": rf"(?:1:)?{user_port}\s+(Enabled|Disabled)\s+([A-Za-z]+)\s+(\d+).*#"}
        case "DGS-3000-24TC":
            return {"command": f"show port_security ports {user_port}",
                    "regex": rf"{user_port}\s+(Enabled|Disabled)\s+([A-Za-z]+)\s+(\d+).*#"}

def show_crc_errors(model: str, user_port: int) -> CommandRegexData:
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DGS-3000-24TC" | "DES-3526":
            return {"command": f"show error ports {user_port}",
                    "regex": r"RX Frames.*?CRC Error\s+(\d+).*#"}
        case "DGS-3120-24TC":
            return {"command": f"show error ports {user_port}",
                    "regex": r"RX Frames.*?CRC Error\s+(\d+).*#"}
        case "DGS-3200-24" | "DES-3200-28":
            return {"command": f"show error ports {user_port}",
                    "regex": r"RX Frames.*?CRC Error\s+(\d+).*CTRL"}

def show_packet(model: str, user_port: int) -> CommandRegexData:
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DGS-3000-24TC" | "DES-3526" | "DGS-3120-24TC":
            return {"command": f"show packet ports {user_port}",
                    "regex": r"Total/(\d)?sec.*RX Bytes\s+\d+\s+(\d+).*TX Bytes\s+\d+\s+(\d+).*#"}
        case "DGS-3200-24" | "DES-3200-28":
            return {"command": f"show packet ports {user_port}",
                    "regex": r"Total/(\d)?sec.*RX Bytes\s+\d+\s+(\d+).*TX Bytes\s+\d+\s+(\d+).*CTRL"}

def show_vlan(model: str) -> CommandRegexData:
    match model:
        case "DES-3028" | "DGS-3120-24TC" | "DGS-3000-24TC" | "DGS-3200-24" | "DES-3200-28" | "DES-3526":
            return {"command": "show vlan",
                    "regex": r"VID\s+:\s+(\d+)\s+VLAN Name\s+:\s+(\S+)"}
        case "DGS-1210-28/ME":
            return {"command": "show vlan",
                    "regex": r"VID\s+:\s+(\d+)\s+VLAN NAME\s+:\s+(\S+)"}

def show_vlan_ports(model: str, user_port: int) -> CommandRegexData:
    match model:
        case "DES-3028" | "DGS-1210-28/ME" | "DES-3200-28":
            return {"command": f"show vlan ports {user_port}",
                    "regex": r"(\d+)\s+(?P<Untagged>[X-])\s+(?P<Tagged>[X-])\s+(?P<Forbidden>[X-])\s+(?P<Dynamic>[X-])"}
        case "DES-3526":
            return {"command": f"show vlan ports {user_port}",
                    "regex": r"(\d+)\s+(?P<Untagged>[X-])\s+(?P<Tagged>[X-])\s+(?P<Forbidden>[X-])\s+(?P<Dynamic>[X-])\s+(?P<RadiusAssigned>[X-])"}
        case "DGS-3120-24TC" | "DGS-3000-24TC" | "DGS-3200-24":
            return {"command": f"show vlan ports {user_port}",
                    "regex": r"(\d+)\s+(?P<Untagged>[X-])\s+(?P<Tagged>[X-])\s+(?P<Dynamic>[X-])\s+(?P<Forbidden>[X-])"}

def show_dhcp_relay(model: str) -> CommandRegexData:
    match model:
        case "DGS-1210-28/ME":
            return {"command": "show dhcp_relay",
                    "servers": r"Interface\s+Server 1\s+Server 2\s+Server 3\s+Server 4\s+(?:-+\s+){5}System\s+(?P<dhcp_server1>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<dhcp_server2>(?:\d{1,3}\.){3}\d{1,3})",
                    "regex": r"DHCP/BOOTP Relay Enable VID List:(?P<vlan_ids_list>[ \S]*)"}
        case "DGS-3120-24TC" | "DGS-3000-24TC":
            return {"command": "show dhcp_relay",
                    "servers": r"Interface\s+Server 1\s+Server 2\s+Server 3\s+Server 4\s+(?:-+\s+){5}System\s+(?P<dhcp_server1>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<dhcp_server2>(?:\d{1,3}\.){3}\d{1,3})",
                    "regex": r"Server\s+VLAN ID List\s+(?:-+\s+){2}(?P<dhcp_server1>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<vlan_ids_list1>\S*)\s+(?P<dhcp_server2>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<vlan_ids_list2>\S*)"}
        case "DES-3028" | "DES-3200-28" | "DES-3526" | "DGS-3200-24":
            return {"command": "show dhcp_relay",
                    "servers": r"Interface\s+Server 1\s+Server 2\s+Server 3\s+Server 4\s+(?:-+\s+){5}System\s+(?P<dhcp_server1>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<dhcp_server2>(?:\d{1,3}\.){3}\d{1,3})"}

def show_access_profile(model: str, user_port: int) -> CommandRegexData:
    match model:
        case "DES-3028":
            return {"command": "show access_profile",
                    "regex": rf"Ports\s+:\s+{user_port}\s+Mode\s+:\s+Permit[\s\S]*?0x([a-z\d]{{8}})\s+0xffffffff"}
        case "DES-3200-28":
            return {"command": "show access_profile",
                    "regex": rf"Ports\s+:\s+{user_port}\s+Mode\s+:\s+Permit[\s\S]*?Value:\s+0x([A-Z\d]{{4}})\s+Mask:\s+0xFFFF[\s\S]*?Value:\s+0x([A-Z\d]{{4}})\s+"}
        case "DES-3526":
            return {"command": "show access_profile",
                    "regex": rf"Mode:\s+Permit\s+Owner\s+:\s+ACL\s+Port\s+:\s+{user_port}\s+-+\s+Offset 16-31 :(?:\s+\S+){{3}}\s+0000([a-z\d]{{4}})\s+Offset 32-47 :\s+0x([a-z\d]{{4}})0000\s+[\s\S]*?Mode:\s+Permit\s+Owner\s+:\s+ACL\s+Port\s+:\s+{user_port}\s+-+\s+Offset 32-47 :\s+0x([a-z\d]{{8}})\s+"}
        case "DGS-1210-28/ME":
            return {"command": "show access_profile",
                    "regex": rf"Mode:\s+Permit\s+Time Range\s+:\s+Ports:\s+{user_port}\s+[\s\S]*?Filter Value = 0x0000([a-z\d]{{4}})\s+[\s\S]*?Filter Value = 0x([a-z\d]{{4}})0000\s+[\s\S]*?Mode:\s+Permit\s+Time Range\s+:\s+Ports:\s+{user_port}\s+[\s\S]*?Filter Value = 0x([a-z\d]{{8}})\s+"}
        case "DGS-3120-24TC":
            return {"command": "show access_profile",
                    "regex": rf"Ports:\s+(?:1:)?{user_port}\s+[\s\S]*?value : 0x0000([A-Z\d]{{4}})\s+[\s\S]*?value : 0x([A-Z\d]{{4}})0000\s+Mask : \S+\s+Action:\s+Permit[\s\S]*?Ports:\s+(?:1:)?{user_port}\s+[\s\S]*?value : 0x([A-Z\d]{{8}})\s+Mask : \S+\s+Action:\s+Permit"}
        case "DGS-3000-24TC" | "DGS-3200-24":
            return {"command": "show access_profile",
                    "regex": rf"Ports:\s+{user_port}\s+[\s\S]*?value : 0x0000([A-Z\d]{{4}})\s+[\s\S]*?value : 0x([A-Z\d]{{4}})0000\s+Mask : \S+\s+Action:\s+Permit[\s\S]*?Ports:\s+{user_port}\s+[\s\S]*?value : 0x([A-Z\d]{{8}})\s+Mask : \S+\s+Action:\s+Permit"}

def show_log(model: str, user_port: int) -> CommandRegexData:
    match model:
        case "DES-3028" | "DGS-3200-24" | "DES-3200-28":
            return {"command": "show log",
                    "format": "%Y-%m-%d %H:%M:%S",
                    "login_and_first": r"(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})\s+Successful login[\s\S]*(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})",
                    "first": r"[\s\S]*(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})",
                    "regex": rf"(\d{{4}}-\d{{2}}-\d+)\s+(\d{{2}}:\d{{2}}:\d{{2}})\s+Port {user_port}",
                    "findall": f"Port {user_port} link up"}
        case "DES-3526":
            return {"command": "show log",
                    "format": "%Y/%m/%d %H:%M:%S",
                    "login_and_first": r"(\d{4}/\d{2}/\d+)\s+(\d{2}:\d{2}:\d{2})\s+Successful login[\s\S]*(\d{4}/\d{2}/\d+)\s+(\d{2}:\d{2}:\d{2})",
                    "first": r"[\s\S]*(\d{4}/\d{2}/\d+)\s+(\d{2}:\d{2}:\d{2})",
                    "regex": rf"(\d{{4}}/\d{{2}}/\d+)\s+(\d{{2}}:\d{{2}}:\d{{2}})\s+Port {user_port}",
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
                    "login_and_first": r"(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+Successful login[\s\S]*(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})",
                    "first": r"[\s\S]*(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})",
                    "regex": rf"(\d{{4}}-\d{{2}}-\d+)\s+(\d{{2}}:\d{{2}}:\d{{2}})\s+\S+\s+Port (?:1:)?{user_port}",
                    "findall": f"Port (?:1:)?{user_port} link up"}
        case "DGS-3000-24TC":
            return {"command": "show log",
                    "format": "%Y-%m-%d %H:%M:%S",
                    "login_and_first": r"(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+Successful login[\s\S]*(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})",
                    "first": r"[\s\S]*(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})",
                    "regex": rf"(\d{{4}}-\d{{2}}-\d+)\s+(\d{{2}}:\d{{2}}:\d{{2}})\s+\S+\s+Port {user_port}",
                    "findall": f"Port {user_port} link up"}


##### COMMANDS FOR L3 GATEWAY #####

def show_ip_interface(model: str, vlan_id: int, vlan_name: str, ipif_name: str) -> CommandRegexData:
    match model:
        case x if x == CISCO_SWITCH:
            return {"command": f"show ip interface vlan {vlan_id}",
                    "regex": rf"IP address is ((?:\d{{1,3}}\.){{3}}\d{{1,3}})/(\d+)"}
        case "DGS-3120-24TC":
            return {"command": f"show ipif {ipif_name}",
                    "showall": "show ipif",
                    "regex": rf"VLAN Name\s+:\s+{vlan_name}\s+Interface Admin State\s+:\s+Enabled\s+Link Status\s+:\s+LinkUp\s+IPv4 Address\s+:\s+((?:\d{{1,3}}\.){{3}}\d{{1,3}})/(\d+)"}
        case _:
            return {"command": f"show ipif {ipif_name}",
                    "showall": "show ipif",
                    "regex": rf"VLAN Name\s+:\s+{vlan_name}\s+Interface Admin State\s+:\s+Enabled\s+IPv4 Address\s+:\s+((?:\d{{1,3}}\.){{3}}\d{{1,3}})/(\d+)"}

def show_ip_route(model: str, user_ip: str) -> CommandRegexData:
    match model:
        case x if x == CISCO_SWITCH:
            return {"command": "show ip route static",
                    "regex": rf"{user_ip}/32\s+via\s+(?P<next_hop>(\d{{1,3}}\.){{3}}\d{{1,3}})(,\s+vlan(\d+))?"}
        case _:
            return {"command": f"show iproute {user_ip} static",
                    "regex": rf"{user_ip}/32\s+(?P<next_hop>(\d{{1,3}}\.){{3}}\d{{1,3}})",
                    "subnet_regex": r"((\d{1,3}\.){3}\d{1,3})/(?P<mask>\d{2})\s+(?P<next_hop>(\d{1,3}\.){3}\d{1,3})"}

def show_arp_ip(model: str, user_ip: str) -> CommandRegexData:
    match model:
        case x if x == CISCO_SWITCH:
            return {"command": f"show arp {user_ip}",
                    "regex": rf"{user_ip}\s+(?P<mac>([A-Z\d]{{2}}-){{5}}[A-Z\d]{{2}})\s+vlan(\d+)"}
        case _:
            return {"command": f"show arpentry ipaddress {user_ip}",
                    "regex": rf"(\S+)\s+{user_ip}\s+(?P<mac>([A-Z\d]{{2}}-){{5}}[A-Z\d]{{2}})"}

def show_arp_mac(model: str, user_mac: str) -> CommandRegexData:
    match model:
        case x if x == CISCO_SWITCH:
            return {"command": f"show arp {user_mac}",
                    "regex": rf"(?P<ip>(\d{{1,3}}\.){{3}}\d{{1,3}})\s+{user_mac}\s+vlan(\d+)"}
        case _:
            return {"command": f"show arpentry mac_address {user_mac}",
                    "regex": rf"(\S+)\s+(?P<ip>(\d{{1,3}}\.){{3}}\d{{1,3}})\s+{user_mac}"}

def show_fdb_L3(model: str, user_mac: str) -> CommandRegexData:
    match model:
        case x if x == CISCO_SWITCH:
            return {"command": f"show mac-address-table address {user_mac}",
                    "regex": rf"(\d+)\s+({user_mac})"}
        case _:
            return {"command": f"show fdb mac_address {user_mac}",
                    "regex": rf"(\d+)\s+(\S+)\s+({user_mac})"}
