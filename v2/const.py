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

    ZERO_32_BYTE_HEX = "0x" + "0" * 64

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