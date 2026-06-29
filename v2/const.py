#!/usr/bin/python3
from typing import Final
from pysnmp.proto.rfc1902 import Integer, OctetString, IpAddress
from dotenv import load_dotenv, find_dotenv
from enum import StrEnum, auto
load_dotenv(find_dotenv())   # find .env file
import os
import json


class Database:
    USERNUM: Final[str] = "Number"

class Country:
    NSERV_NNET: Final[int] = int(os.getenv("COUNTRY_NSERV_NNET"))

# enum for request types
class SNMPRequestType(StrEnum):
    GET = auto()
    SET = auto()

# enum for config sections in yaml, names are specified for clarity
class SwitchConfigSection(StrEnum):
    PRIVATE_MIBS = "private_mibs"
    SWITCH = "switch"
    TRUSTED_HOST = "trusted_host"
    ACL = "acl"
    VLAN = "vlan"
    FDB = "fdb"
    IPIF = "ipif"
    DHCP_RELAY = "dhcp_relay"
    ARP = "arp"
    PORT = "port"

class SNMP:
    READ_ONLY = os.getenv("SNMP_READ_ONLY")
    READ_WRITE = os.getenv("SNMP_READ_WRITE")
    TEST_3028 = os.getenv("SNMP_TEST_3028")
    TEST_1210 = os.getenv("SNMP_TEST_1210")

    DEFAULT_IP = "10.90.90.90"

    # mapping for formatting patterns with struct module, bytes_count: format_symbol
    PATTERN_MAPPING = {"1": "B", "2": "H", "4": "I", "8": "Q"}

    # map vlan status to ports param name
    PARAM_FOR_VLAN_STATUS = {"untagged": "untagged_ports", "tagged": "egress_ports"}

    ZERO_VLAN_NAME = "0x" + "0" * 64
    ZERO_MAC_ADDRESS = "00-00-00-00-00-00"
    ZERO_ETHERNET_TYPE = "0x0000"
    ZERO_OFFSET_CHUNK = "0x00000000"

    SOURCE_IP_BYTES_IN_IPV4 = {26, 27, 28, 29}
    SOURCE_IP_OFFSET_IN_IPV4 = 26
    SOURCE_IP_BYTES_IN_ARP = {28, 29, 30, 31}
    SOURCE_IP_OFFSET_IN_ARP = 28

    @staticmethod
    def typify_mac_address(mac_address: str) -> OctetString:
        return OctetString(bytes.fromhex(mac_address.replace("-", "")))

    TYPE = {
        "integer": Integer,
        "octetstring": OctetString,
        "hexstring": lambda val: OctetString(hexValue=val.removeprefix("0x")),
        "ipaddress": IpAddress,
        "macaddress": typify_mac_address
    }