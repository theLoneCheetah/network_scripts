#!/usr/bin/python3
from typing import Final
from ipaddress import IPv4Address, IPv4Network
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())   # find .env file
import os
import json


##### DATABASE FIELDS AND CONSTANTS #####

class Database:
    # convert fields from database to useful program names
    KEY_FIELD: Final[dict[str, str]] = {"Vznos": "payment",
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
    KEY_OUTPUT: Final[dict[str, str]] = {"ip": "IP-адрес",
                  "mask": "Маска",
                  "gateway": "Шлюз",
                  "switch": "Свитч статич.",
                  "port": "Порт статич.",
                  "dhcp": "Тип DHCP",
                  "public_ip": "Внешний IP",
                  "nserv": "Nserv",
                  "nnet": "Nnet"}
    
    # usernum field name
    USERNUM: Final[str] = "Number"
    
    # speed by payments (vznos), country payments, 555 is an exception
    NEW_PAYMENT: Final[int] = 555
    FAST_ETHERNET: Final[set[int]] = {52, 53, 54, 75, 301, 303, 330, 400, 490, 492, 494, 497, 503, 508, 509, 580, 582, 583, 586, 592, 598, 666, 667, 1000, 1300, 1500, 2000}
    GIGABIT_ETHERNET: Final[set[int]] = {650, 652, 653, 656, 662, 668, 720, 722, 723, 726, 732, 738, 950, 951, 952, 953, 956, 962, 968, 1330, 1530}
    INACTIVE_PAYMENT: Final[set[int]] = {10, 48, 49, 95, 96, 97, 98, 99}
    COUNTRY_PAYMENT: Final[set[int]] = {801, 1001, 1006, 1012, 1501, 1506, 1512, 2001, 2006, 2012}
    MAX_KNOWN_PAYMENT: Final[int] = 2099   # more than 2100 let's decide if there's gigabit


##### MAIN PROVIDER SETTINGS AND CONSTANTS FOR CITY #####

class Provider:    
    # network has nnets and nservs from 1 to 1016 now
    LAST_NSERV_NNET: Final[int] = int(os.getenv("LAST_NSERV_NNET"))
    LAST_PORT: Final[int] = 52
    
    # fields with checking limits
    NUMBER_FIELDS_LIMITS: Final[dict[str, int]] = {"port": LAST_PORT, "dhcp": 1, "nserv": LAST_NSERV_NNET, "nnet": LAST_NSERV_NNET}
    IP_FIELDS: Final[set[str]] = {"ip", "mask", "gateway", "switch", "public_ip"}

    # network local addresses
    FIRST_LOCAL_IP: Final[IPv4Address] = IPv4Address(os.getenv("FIRST_LOCAL_IP"))
    LAST_LOCAL_IP: Final[IPv4Address] = IPv4Address(os.getenv("LAST_LOCAL_IP"))
    SWITCH_OTHER_LOCAL_SUBNET: Final[IPv4Network] = IPv4Network(os.getenv("SWITCH_OTHER_LOCAL_SUBNET"))
    
    # range of local masks
    LOCAL_MASKS: Final[range] = range(*json.loads(os.getenv("LOCAL_MASKS_RANGE")))

    # set of network public subnets
    PUBLIC_GATEWAY_MASK: Final[dict[str, int]] = json.loads(os.getenv("PUBLIC_GATEWAY_MASK"))
    PUBLIC_SUBNETS: Final[set[IPv4Network]] = {IPv4Network(f"{gateway}/{mask}", strict=False) for gateway, mask in PUBLIC_GATEWAY_MASK.items()}

    # dhcp servers
    PRIMARY_DHCP_SERVER: Final[str] = os.getenv("PRIMARY_DHCP_SERVER")
    SECONDARY_DHCP_SERVERS: Final[set[str]] = set(json.loads(os.getenv("SECONDARY_DHCP_SERVERS")))
    
    # vlan constants
    DIRECT_PUBLIC_VLAN: Final[int] = int(os.getenv("DIRECT_PUBLIC_VLAN"))
    VLAN_SKIPPING: Final[set[int]] = set(json.loads(os.getenv("VLAN_SKIPPING")))
    
    # on Lensoveta 23 OSPF protocol is used, default gateway address doesn't have static ip route
    LENSOVETA_ADDRESS_GATEWAY: Final[dict[str, int | str]] = {"street": 33, "house": "23", "gateway": os.getenv("LENSOVETA_23_GATEWAY")}


##### CONSTANTS FOR CITY SWITCH DIAGNOSTICS #####

class CitySwitch:
    # types of cli to identify model
    CLI_TYPES: Final[list[str]] = ["d-link", "cisco"]

    # port speed
    NORMAL_SPEED: Final[dict[bool, str]] = {False: "100M/Full", True: "1000M/Full"}

    # vlan statuses
    VLAN_STATUSES: Final[list[str]] = ["Untagged", "Tagged", "Forbidden", "Dynamic", "RadiusAssigned"]

    # for log scanning
    MAX_MINUTE_RANGE_PORT_FLAPPING: Final[int] = 10
    LAST_FLAP_MAX_MINUTE_REMOTENESS: Final[int] = 2
    MIN_COUNT_FLAPPING: Final[int] = 20

    # max hops number for direct public ip routes
    MAX_HOPS_DIRECT_PUBLIC_IP: Final[int] = 3


##### COUNTRY SETTINGS #####

class Country:
    # record fields
    NUMBER_FIELDS: Final[set[str]] = {"nserv", "nnet"}
    IP_FIELDS: Final[set[str]] = {"ip", "public_ip"}
    UNUSED_NUMBER_FIELDS: Final[set[str]] = {"port", "dhcp"}
    UNUSED_IP_FIELDS: Final[set[str]] = {"mask", "gateway", "switch"}

    # country's unified mask, main subnets and vlans
    MASK: Final[str] = os.getenv("COUNTRY_MASK")
    MASK_LENGTH: Final[str] = IPv4Network(f"0.0.0.0/{MASK}").prefixlen
    VLAN_GATEWAY: Final[dict[str, int]] = {int(key): val for key, val in json.loads(os.getenv("COUNTRY_VLAN_GATEWAY")).items()}
    SUBNETS: Final[set[IPv4Network]] = set(map(lambda gateway, mask=MASK: IPv4Network(f"{gateway}/{mask}", strict=False), VLAN_GATEWAY.values()))

    # nserv and nnet
    NSERV_NNET: Final[int] = int(os.getenv("COUNTRY_NSERV_NNET"))

    # url for all configured onts, no matter online or not
    ALARM_URL: Final[str] = os.getenv("URL_CONFIGURED_ONTS")

    # ip addresses of olt swtiches version 2 and 3
    OLTS_VERSION2: Final[set[str]] = set(json.loads(os.getenv("OLTS_VERSION2")))
    OLTS_VERSION3: Final[set[str]] = set(json.loads(os.getenv("OLTS_VERSION3")))

    # unified gateway
    ACTUAL_GATEWAY: Final[str] = os.getenv("COUNTRY_ACTUAL_GATEWAY")

    # log flapping
    MAX_MINUTE_RANGE_ONT_FLAPPING: Final[int] = 10
    MIN_COUNT_FLAPPING: Final[int] = 4

    # rssi
    HIGH_RSSI: Final[float] = -30.0

##### PACKET SCANNING CONSTANTS #####

class PacketScan:
    # pipe for packet scanning path
    PIPE: Final[str] = os.getenv("PIPE")
