#!/usr/bin/python3
from ipaddress import IPv4Address, IPv4Network
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())   # find .env file
import os
import json


##### PROGRAM CONSTANTS #####

class CONST:
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
    last_nserv_nnet = int(os.getenv("LAST_NNET_NSERV"))
    last_port = 52
    
    # fields checking limits
    number_fields_limits = {"port": last_port, "dhcp": 1, "nserv": last_nserv_nnet, "nnet": last_nserv_nnet}
    ip_fields = {"ip", "mask", "gateway", "switch", "public_ip"}

    # network local addresses
    first_local_ip = IPv4Address(os.getenv("FIRST_LOCAL_IP"))
    last_local_ip = IPv4Address(os.getenv("LAST_LOCAL_IP"))
    switch_other_local_subnet = IPv4Network(os.getenv("SWITCH_OTHER_LOCAL_SUBNET"))
    
    # range of local masks
    local_masks = range(*json.loads(os.getenv("LOCAL_MASKS_RANGE")))

    # set of network public subnets
    public_gateway_mask = json.loads(os.getenv("PUBLIC_GATEWAY_MASK"))
    public_subnets = {IPv4Network(subnet, strict=False) for subnet in map(lambda x, pg=public_gateway_mask: f"{x}/{pg[x]}", public_gateway_mask)}

    # dhcp servers
    primary_dhcp_server = os.getenv("PRIMARY_DHCP_SERVER")
    secondary_dhcp_servers = json.loads(os.getenv("SECONDARY_DHCP_SERVERS"))

    # variables and expressions while diagnosting
    normal_speed = {False: "100M/Full", True: "1000M/Full"}
    vlan_statuses = ["Untagged", "Tagged", "Forbidden", "Dynamic", "RadiusAssigned"]
    direct_public_vlan = int(os.getenv("DIRECT_PUBLIC_VLAN"))
    vlan_skipping = json.loads(os.getenv("VLAN_SKIPPING"))
    max_minute_range_port_flapping = 10
    last_flap_max_minute_remoteness = 2
    min_count_flapping = 20
    
    # types of cli to identify model
    cli_types = ["d-link", "cisco"]
    
    # on Lensoveta 23 OSPF protocol is used, default gateway address doesn't have static ip route
    lensoveta_address_gateway = {"street": 33, "house": "23", "gateway": os.getenv("LENSOVETA_23_GATEWAY")}

    # pipe for packet scanning path
    PIPE = os.getenv("PIPE")