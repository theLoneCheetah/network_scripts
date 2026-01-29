#!/usr/bin/python3
from typing import Protocol


##### L2 MANAGER PROTOCOL FOR CITY AND COUNTRY #####

class L2Protocol(Protocol):
    # L2 switch manager should be able to find and return a set of mac addresses
    def get_mac_addresses(self) -> set[str]:
        ...