#!/usr/bin/python3
import asyncio
import yaml
import struct
import re
from typing import Any, Self, Union, TypeAlias
from abc import ABC, abstractmethod
from icmplib import ping
from pysnmp.hlapi.v3arch.asyncio import *
from pyasn1.type.univ import ObjectIdentifier
from pysnmp.proto.rfc1902 import OctetString, Integer, IpAddress
from const import SNMP
from snmp_exceptions import *

type SnmpValue = ObjectIdentifier | OctetString | Integer | IpAddress
type PayloadData = dict[str, dict[str, Any]]

class SNMPClient(ABC):
    _ipaddress: str
    _model: str
    _init_lock: asyncio.Lock
    _engine: SnmpEngine
    _read_community: CommunityData
    _write_community: CommunityData
    _transport: UdpTransportTarget
    _context: ContextData
    _max_repetitions: int
    _config: dict[str, Any]

    def __init__(self, ipaddress: str) -> None:
        self._ipaddress = ipaddress
        self._model = None

        self._init_lock = asyncio.Lock()
        self._engine = None
        self._read_community = None
        self._write_community = None
        self._transport = None
        self._context = None
        self._max_repetitions = 49   # can be changed

        with open("v2/oid.yaml", "r") as F:
            self._config = yaml.safe_load(F)
    
    @classmethod
    async def create(cls, ipaddress: str, *args, **kwargs) -> Self:
        self = cls(ipaddress, *args)

        assert_switch_models = kwargs.get("assert_switch_models")
        await self._initialize(assert_switch_models=assert_switch_models)

        # if only model assertion needed, post init isn't necessary
        if "assert_switch_models" not in kwargs:
            self._post_init()
        
        return self
    
    async def _initialize(self, assert_switch_models: set[str] | None = None) -> None:
        async with self._init_lock:
            if self._engine is not None:
                return
            
            self._engine = SnmpEngine()
            self._read_community = CommunityData(SNMP.READ_ONLY)
            self._write_community = CommunityData(SNMP.READ_WRITE)
            self._transport = await UdpTransportTarget.create((self._ipaddress, 161), retries=2)
            self._context = ContextData()

            await self._identify(assert_switch_models)
    
    async def _identify(self, assert_switch_models: set[str]) -> None:
        task_oid = asyncio.create_task(self._get(SNMPClient._filter_request_config(self._config["system"], ["private_oid"]), True))
        task_description = asyncio.create_task(self._get(SNMPClient._filter_request_config(self._config["system"], ["description"]), True))
        models, description = await asyncio.gather(task_oid, task_description)

        models = next(iter(models.values()))
        description = next(iter(description.values()))
        
        for model in models:
            if model in description:   # description must contain one of model names from config
                self._model = model
                break
        else:
            raise AssertionError(f"Switch model with ip {self._ipaddress} was not found in description")
        
        # check switch model with defined one and print error if assertion failed
        if assert_switch_models:
            try:
                assert self._model in assert_switch_models
            except AssertionError:
                print(f"AssertionError: the switch model with ip {self._ipaddress} is {self._model}, not {assert_switch_models}")
    
    @abstractmethod
    def _post_init(self) -> None:
        pass
    
    def _wait_for_device_online(self) -> bool:
        for _ in range(240):
            if ping(self._ipaddress, count=1, timeout=1, privileged=False).is_alive:
                return True
        return False
    
    async def _get(self, payload: PayloadData, skip_init: bool = False) -> dict[str, Any] | None:
        if not skip_init:
            await self._initialize()
        
        oid_objects = [ObjectType(ObjectIdentity(self._render_get_set_oid(request["oid"], **request["params"]))) for request in payload.values()]
        
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            self._engine,
            self._read_community,
            self._transport,
            self._context,
            *oid_objects
        )
        
        try:
            SNMPClient._check_errors(errorIndication, errorStatus, errorIndex, varBinds, payload)
        except SNMPTransportError:
            raise
        except SNMPProtocolError:
            raise
        
        results = {}

        for (command_name, data), varBind in zip(payload.items(), varBinds):
            results[command_name] = SNMPClient._handle_result_value(varBind[1], data)
        
        return results
    
    async def _set(self, payload: PayloadData) -> dict[str, Any] | None:
        await self._initialize()
        
        for data in payload.values():
            if "values" in data:
                set_value = next(key for key, value in data["values"].items() if value == data["set_value"])
            else:
                set_value = data["set_value"]
            data["set_value"] = SNMP.TYPE[data["value_type"]](set_value)
        
        oid_objects = [ObjectType(ObjectIdentity(self._render_get_set_oid(request["oid"], **request["params"])), request["set_value"]) for request in payload.values()]
        
        errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
            self._engine,
            self._write_community,
            self._transport,
            self._context,
            *oid_objects
        )
        
        try:
            SNMPClient._check_errors(errorIndication, errorStatus, errorIndex, varBinds, payload)
        except SNMPTransportError:
            raise
        except SNMPProtocolError:
            raise
        
        results = {}

        for (command_name, data), varBind in zip(payload.items(), varBinds):
            results[command_name] = SNMPClient._handle_result_value(varBind[1], data)
        
        return results
    
    async def _bulk_walk(self, payload: dict[str, Any]) -> list[tuple[str, Any]] | None:
        await self._initialize()

        oid_object = ObjectType(ObjectIdentity(self._render_bulk_walk_oid(payload["oid"])))

        results = []

        async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
            self._engine,
            self._read_community,
            self._transport,
            self._context,
            0, self._max_repetitions,
            oid_object,
            lexicographicMode=False
        ):
            try:
                SNMPClient._check_errors(errorIndication, errorStatus, errorIndex, varBinds, payload)
            except SNMPTransportError:
                raise
            except SNMPProtocolError:
                raise
            
            for varBind in varBinds:
                oid = str(varBind[0])
                value = SNMPClient._handle_result_value(varBind[1], payload)
                results.append((oid, value))
        
        return results
    
    async def _action_after_system_reboot(self, system_reboot_mode: str) -> None:
        if system_reboot_mode == "reset_config_and_reboot":
            self._ipaddress = SNMP.DEFAULT_IP
            if self._wait_for_device_online():
                self._transport = await UdpTransportTarget.create((self._ipaddress, 161), retries=2)
            else:
                raise RuntimeError("Failed to establish connection with device with ip:", self._ipaddress)

        elif not self._wait_for_device_online():
            raise RuntimeError("Failed to reestablish connection with device with ip:", self._ipaddress)
        
        # profilactic tries to reestablish connection with snmp agent
        for i in range(10):
            try:
                await self._identify()
                break
            except SNMPTransportError:
                continue
        else:
            raise RuntimeError("Failed to reestablish connection with device's SNMP agent with ip:", self._ipaddress)
    
    async def _action_after_ip_address_change(self, ip: str) -> None:
        old_ip = self._ipaddress
        self._ipaddress = ip
        self._transport = await UdpTransportTarget.create((self._ipaddress, 161), retries=2)

        try:
            await self._identify()
        except SNMPTransportError:
            self._ipaddress = old_ip
            self._transport = await UdpTransportTarget.create((self._ipaddress, 161), retries=2)
            raise RuntimeError("Failed to identify device with ip:", ip)
    
    @staticmethod
    def _filter_request_config(config_fragment: dict[str, Any], include_oids: list[str]) -> PayloadData:
        return {key: {**config_fragment[key], "params": {}} for key in include_oids if key in config_fragment}
    
    @staticmethod
    def _check_errors(errorIndication, errorStatus, errorIndex, varBinds, payload: PayloadData) -> None:
        if errorIndication:
            raise SNMPTransportError(errorIndication)
        
        if errorStatus:
            raise SNMPProtocolError(str(errorStatus), int(errorIndex), list(payload.keys()))

    @staticmethod
    def _handle_result_value(value: SnmpValue, data: str) -> str | int:
        if value.isSameTypeWith(NoSuchInstance()):
            return None
        
        value = value.prettyPrint()

        match data["value_type"]:
            case "integer":
                value = int(value)
                if "values" in data:
                    value = data["values"][value]
            case "octetstring":
                # value = bytes.fromhex(value[2:]).decode("utf-8")   # for SNR-S2995G-48FX description
                if "bytes_pattern" in data:
                    value = SNMPClient._split_octet_by_pattern(value, data["bytes_pattern"])
            case "hexstring":
                pass
            case "ipaddress":
                pass
            case "macaddress":
                value = SNMPClient._convert_octet_string_into_mac(value)
            case "objectid":
                if "values" in data:
                    value = data["values"][value]
        
        return value
    
    @staticmethod
    def _split_octet_by_pattern(octet_string: str, pattern: str) -> tuple[int]:
        bytes_string = bytes.fromhex(octet_string[2:])

        mapping = {"1": "B", "2": "H", "4": "I", "8": "Q"}
        fmt = ">" + "".join(mapping[bytes_count] for bytes_count in pattern)
        
        return struct.unpack(fmt, bytes_string)
    
    @staticmethod
    def _convert_octet_string_into_mac(octet_string: str) -> str:
        return "-".join([octet_string[2*i:2*i+2].upper() for i in range(1, 7)])

    @abstractmethod
    def _render_get_set_oid(self, oid: str, **params) -> str:
        pass

    @staticmethod
    def _render_bulk_walk_oid(oid: str) -> str:
        return re.sub(r"\.{.*", "", oid)