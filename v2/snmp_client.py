#!/usr/bin/python3
import asyncio
import yaml
from pysnmp.hlapi.v3arch.asyncio import *
from const import SNMP

class SNMPClient:
    _ipaddress: str
    _port: int
    _config: dict
    _engine: SnmpEngine

    def __init__(self, ipaddress: str, port: int) -> None:
        self._ipaddress = ipaddress
        self._port = port
        self._config = None

        self._engine = None
        self._community = None
        self._transport = None
        self._context = None
    
    async def _initialize(self):
        if self._engine is None:
            self._engine = SnmpEngine()
            self._community = CommunityData(SNMP.READ_ONLY)
            self._transport = await UdpTransportTarget.create((SNMP.TEST_3028, 161))
            self._context = ContextData()

            with open("v2/oid.yaml", "r") as F:
                self._config = yaml.safe_load(F)
    
