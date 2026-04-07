#!/usr/bin/python3
from typing import Final
from ipaddress import IPv4Address, IPv4Network
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())   # find .env file
import os
import json


class SNMP:
    READ_ONLY = os.getenv("SNMP_READ_ONLY")
    READ_WRITE = os.getenv("SNMP_READ_WRITE")
    TEST_3028 = os.getenv("SNMP_TEST_3028")
    TEST_1210 = os.getenv("SNMP_TEST_1210")
