#!/usr/bin/python3
from typing import Final
from pysnmp.proto.rfc1902 import Integer, OctetString, IpAddress
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())   # find .env file
import os
import json


class Database:
    USERNUM: Final[str] = "Number"

class SNMP:
    READ_ONLY = os.getenv("SNMP_READ_ONLY")
    READ_WRITE = os.getenv("SNMP_READ_WRITE")
    TEST_3028 = os.getenv("SNMP_TEST_3028")
    TEST_1210 = os.getenv("SNMP_TEST_1210")

    DEFAULT_IP = "10.90.90.90"

    ZERO_VLAN_NAME = "0x" + "0" * 64
    ZERO_MAC_ADDRESS = "00-00-00-00-00-00"
    ZERO_ETHERNET_TYPE = "0x0000"
    ZERO_OFFSET_CHUNK = "0x00000000"

    SOURCE_IP_BYTES_IN_IPV4 = [26, 27, 28, 29]
    SOURCE_IP_BYTES_IN_ARP = [28, 29, 30, 31]

    @staticmethod
    def typify_mac_address(mac_address: str) -> OctetString:
        print(repr(mac_address), type(mac_address))
        return OctetString(bytes.fromhex(mac_address.replace("-", "")))

    TYPE = {
        "integer": Integer,
        "octetstring": OctetString,
        "ipaddress": IpAddress,
        "macaddress": typify_mac_address
    }