#!/usr/bin/python3
import asyncio
import yaml
from typing import Any
from abc import abstractmethod
from pysnmp.hlapi.v3arch.asyncio import *
from const import SNMP

class SNMPClient:
    _ipaddress: str
    _init_lock: asyncio.Lock
    _engine: SnmpEngine
    _community: CommunityData
    _transport: UdpTransportTarget
    _context: ContextData
    _config: dict[str, Any]

    def __init__(self, ipaddress: str) -> None:
        self._ipaddress = ipaddress

        self._init_lock = asyncio.Lock()
        self._engine = None
        self._community = None
        self._transport = None
        self._context = None

        with open("v2/oid.yaml", "r") as F:
            self._config = yaml.safe_load(F)
    
    async def _initialize(self) -> None:
        async with self._init_lock:
            if self._engine is None:
                self._engine = SnmpEngine()
                self._community = CommunityData(SNMP.READ_ONLY)
                self._transport = await UdpTransportTarget.create((self._ipaddress, 161))
                self._context = ContextData()
    
    async def _get(self, config_fragment: dict[str, Any]) -> dict[str, Any] | None:
        await self._initialize()

        request_data = [{"command": command, **data} for command, data in config_fragment.items()]
        oid_objects = [ObjectType(ObjectIdentity(self._render_oid(request["oid"]))) for request in request_data]

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            self._engine,
            self._community,
            self._transport,
            self._context,
            *oid_objects
        )
        
        if errorIndication:
            print("SNMP error:", errorIndication)
            return None
        
        if errorStatus:
            print("SNMP error:", errorStatus)
            return None
        
        results = {}

        for data, varBind in zip(request_data, varBinds):
            if data["type"] == "integer" and "values" in data:
                results[data["command"]] = data["values"][int(varBind[1].prettyPrint())]
            else:
                results[data["command"]] = varBind[1].prettyPrint()
        
        return results
    
    async def _bulk_walk(self, request_data: dict[str, Any]) -> list[tuple[str, Any]] | None:
        await self._initialize()

        oid_object = ObjectType(ObjectIdentity(self._render_oid(request_data["oid"])))
        max_repetitions = 49   # can be changed

        results = []

        async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
            self._engine,
            self._community,
            self._transport,
            self._context,
            0, max_repetitions,
            oid_object,
            lexicographicMode=False
        ):
            if errorIndication:
                print("SNMP error:", errorIndication)
                return None
            
            if errorStatus:
                print("SNMP error:", errorStatus)
                return None
            
            for varBind in varBinds:
                oid = str(varBind[0])

                if request_data["type"] == "integer":
                    value = int(varBind[1].prettyPrint())
                    if "values" in request_data:
                        value = request_data["values"][value]
                else:
                    value = varBind[1].prettyPrint()

                results.append((oid, value))
        
        return results
    
    def _filter_request_config(self, config_fragment: dict[str, Any], include_oids: list[str]) -> dict[str, Any]:
        return {key: config_fragment[key] for key in include_oids if key in config_fragment}

    @abstractmethod
    def _render_oid(self, oid: str) -> str:
        pass