#!/usr/bin/python3
from ipaddress import IPv4Address, IPv4Network
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())   # find .env file
import os
import json


##### DATABASE FIELDS AND CONSTANTS #####

class Database:
    # convert fields from database to useful program names
    KEY_FIELD = {"Vznos": "payment",
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
    KEY_OUTPUT = {"ip": "IP-адрес",
                  "mask": "Маска",
                  "gateway": "Шлюз",
                  "switch": "Свитч статич.",
                  "port": "Порт статич.",
                  "dhcp": "Тип DHCP",
                  "public_ip": "Внешний IP",
                  "nserv": "Nserv",
                  "nnet": "Nnet"}
    
    # usernum field name
    USERNUM = "Number"
    
    # speed by payments (vznos), country payments, 555 is an exception
    NEW_PAYMENT = 555
    FAST_ETHERNET = {52, 53, 54, 301, 303, 330, 400, 490, 492, 494, 497, 503, 508, 509, 580, 582, 583, 586, 592, 598, 666, 667, 1000, 1300, 2000}
    GIGABIT_ETHERNET = {650, 652, 653, 656, 662, 668, 720, 722, 723, 726, 732, 738, 950, 951, 952, 953, 956, 962, 968, 1330}
    INACTIVE_PAYMENT = {10, 48, 49, 95, 96, 97, 98, 99}
    COUNTRY_PAYMENT = {801, 1001, 1006, 1012, 1501, 1506, 1512, 2001, 2006, 2012}
    MAX_KNOWN_PAYMENT = 2099   # more than 2100 let's decide there's only gigabit


##### MAIN PROVIDER SETTINGS AND CONSTANTS FOR CITY #####

class Provider:    
    # network has nnets and nservs from 1 to 1016 now
    LAST_NSERV_NNET = int(os.getenv("LAST_NSERV_NNET"))
    LAST_PORT = 52
    
    # fields with checking limits
    NUMBER_FIELDS_LIMITS = {"port": LAST_PORT, "dhcp": 1, "nserv": LAST_NSERV_NNET, "nnet": LAST_NSERV_NNET}
    IP_FIELDS = {"ip", "mask", "gateway", "switch", "public_ip"}

    # network local addresses
    FIRST_LOCAL_IP = IPv4Address(os.getenv("FIRST_LOCAL_IP"))
    LAST_LOCAL_IP = IPv4Address(os.getenv("LAST_LOCAL_IP"))
    SWITCH_OTHER_LOCAL_SUBNET = IPv4Network(os.getenv("SWITCH_OTHER_LOCAL_SUBNET"))
    
    # range of local masks
    LOCAL_MASKS = range(*json.loads(os.getenv("LOCAL_MASKS_RANGE")))

    # set of network public subnets
    PUBLIC_GATEWAY_MASK = json.loads(os.getenv("PUBLIC_GATEWAY_MASK"))
    PUBLIC_SUBNETS = {IPv4Network(f"{gateway}/{mask}", strict=False) for gateway, mask in PUBLIC_GATEWAY_MASK.items()}

    # dhcp servers
    PRIMARY_DHCP_SERVER = os.getenv("PRIMARY_DHCP_SERVER")
    SECONDARY_DHCP_SERVERS = set(json.loads(os.getenv("SECONDARY_DHCP_SERVERS")))
    
    # vlan constants
    DIRECT_PUBLIC_VLAN = int(os.getenv("DIRECT_PUBLIC_VLAN"))
    VLAN_SKIPPING = set(json.loads(os.getenv("VLAN_SKIPPING")))
    
    # on Lensoveta 23 OSPF protocol is used, default gateway address doesn't have static ip route
    LENSOVETA_ADDRESS_GATEWAY = {"street": 33, "house": "23", "gateway": os.getenv("LENSOVETA_23_GATEWAY")}


##### CONSTANTS FOR CITY SWITCH DIAGNOSTICS #####

class CitySwitch:
    # types of cli to identify model
    CLI_TYPES = ["d-link", "cisco"]

    # port speed
    NORMAL_SPEED = {False: "100M/Full", True: "1000M/Full"}

    # vlan statuses
    VLAN_STATUSES = ["Untagged", "Tagged", "Forbidden", "Dynamic", "RadiusAssigned"]

    # for log scanning
    MAX_MINUTE_RANGE_PORT_FLAPPING = 10
    LAST_FLAP_MAX_MINUTE_REMOTENESS = 2
    MIN_COUNT_FLAPPING = 20

    # max hops number for direct public ip routes
    MAX_HOPS_DIRECT_PUBLIC_IP = 3


##### COUNTRY SETTINGS #####

class Country:
    # record fields
    NUMBER_FIELDS = {"nserv", "nnet"}
    IP_FIELDS = {"ip", "public_ip"}
    UNUSED_NUMBER_FIELDS = {"port", "dhcp"}
    UNUSED_IP_FIELDS = {"mask", "gateway", "switch"}

    # country's unified mask, main subnets and vlans
    MASK = os.getenv("COUNTRY_MASK")
    GATEWAY_VLAN = json.loads(os.getenv("COUNTRY_GATEWAY_VLAN"))
    SUBNETS = set(map(lambda gateway, mask=MASK: IPv4Network(f"{gateway}/{mask}", strict=False), GATEWAY_VLAN.keys()))

    # nserv and nnet
    NSERV_NNET = int(os.getenv("COUNTRY_NSERV_NNET"))

    # ip addresses of olt swtiches version 2 and 3
    OLT2_SWITCHES = set(json.loads(os.getenv("OLT2_SWITCHES")))
    OLT3_SWITCHES = set(json.loads(os.getenv("OLT3_SWITCHES")))

    # unified gateway
    ACTUAL_GATEWAY = os.getenv("COUNTRY_ACTUAL_GATEWAY")


##### PACKET SCANNING CONSTANTS #####

class PacketScan:
    # pipe for packet scanning path
    PIPE = os.getenv("PIPE")
