#!/usr/bin/python3
import asyncio
import yaml
import struct
import re
from typing import Any, Self
from abc import ABC, abstractmethod
from pprint import pprint
from copy import deepcopy
from icmplib import ping
from pysnmp.hlapi.v3arch.asyncio import *
from pyasn1.type.univ import ObjectIdentifier
from pysnmp.proto.rfc1902 import OctetString, Integer, IpAddress
from const import SNMPRequestType, SNMP
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
    
    async def _identify(self, assert_switch_models: set[str] | None = None) -> None:
        task_oid = asyncio.create_task(
            self._get(
                SNMPClient._compose_request_payload(SNMPRequestType.GET, self._config["system"], ["private_oid"]),
                skip_init=True
            )
        )
        task_description = asyncio.create_task(
            self._get(
                SNMPClient._compose_request_payload(SNMPRequestType.GET, self._config["system"], ["description"]),
                skip_init=True
            )
        )
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
    
    # helper function waiting for device to be online in the certain time range
    def _wait_for_device_online(self) -> bool:
        # 240 seconds of retrying
        for _ in range(240):
            # if alive at any time, return True
            if ping(self._ipaddress, count=1, timeout=1, privileged=False).is_alive:
                return True
        # otherwise False
        return False
    
    async def _get(self, payload: PayloadData, skip_init: bool = False) -> dict[str, Any] | None:
        if not skip_init:
            await self._initialize()
        
        oid_objects = [ObjectType(ObjectIdentity(self._render_get_set_oid(request["oid"], **request["params"])))
                       for request in payload.values()]
        
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
            results[command_name] = SNMPClient._convert_result_value(varBind[1], data)
        
        return results
    
    async def _set(self, payload: PayloadData) -> dict[str, Any] | None:
        await self._initialize()
        
        oid_objects = [ObjectType(ObjectIdentity(self._render_get_set_oid(request["oid"], **request["params"])), request["set_value"])
                       for request in payload.values()]
        
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
            results[command_name] = SNMPClient._convert_result_value(varBind[1], data)
        
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
                value = SNMPClient._convert_result_value(varBind[1], payload)
                results.append((oid, value))
        
        return results
    
    # handle result of switch reboot/reset
    async def _action_after_system_reboot(self, system_reboot_mode: str) -> None:
        # for reset system mode, ip address is default now
        if system_reboot_mode == "reset_config_and_reboot":
            self._ipaddress = SNMP.DEFAULT_IP
            # if device was found online, create new transport and continue work
            if self._wait_for_device_online():
                self._transport = await UdpTransportTarget.create((self._ipaddress, 161), retries=2)
            # raise an exception otherwise
            else:
                raise RuntimeError("Failed to establish connection with device with ip:", self._ipaddress)

        # for reboot, if device was not found online, raise an exception
        elif not self._wait_for_device_online():
            raise RuntimeError("Failed to reestablish connection with device with ip:", self._ipaddress)
        
        # profilactic tries to reestablish connection with snmp agent
        for i in range(10):
            try:
                await self._identify()
                break
            except SNMPTransportError:
                continue
        # if identification failed, raise an exception working with snmp agent
        else:
            raise RuntimeError("Failed to reestablish connection with device's SNMP agent with ip:", self._ipaddress)
    
    # handle result of ip address change
    async def _action_after_ip_address_change(self, ip: str) -> None:
        # remember old ip for backtracking
        old_ip = self._ipaddress
        self._ipaddress = ip
        # create new transport
        self._transport = await UdpTransportTarget.create((self._ipaddress, 161), retries=2)

        try:
            # if identified, everything is fine
            await self._identify()
        except SNMPTransportError:
            # if not, create transport with old ip and raise an exception
            self._ipaddress = old_ip
            self._transport = await UdpTransportTarget.create((self._ipaddress, 161), retries=2)
            raise RuntimeError("Failed to identify device with ip:", ip)
    
    # form payload for request from oid fragment by oids list (get request) or dict (set)
    @staticmethod
    def _compose_request_payload(request_type: SNMPRequestType, config_fragment: dict[str, Any], include_params: list[str] | dict[str, Any]) -> PayloadData:
        result = {}

        # for config fragment, include only specified oids
        for key in include_params:
            if key in config_fragment:
                # deepcopy is needed for keeping nested structure safe
                item = deepcopy(config_fragment[key])
                # include default params key
                item["params"] = {}

                # include set_value for set requests
                if request_type == SNMPRequestType.SET:
                    set_value = include_params[key]

                    # integer values specified by string name, find integer key associated with name
                    if "values" in item:
                        set_value = next(key for key, value in item["values"].items() if value == set_value)
                    
                    if bytes_pattern := item.get("bytes_pattern"):
                        set_value = SNMPClient._build_octet_by_pattern(set_value, bytes_pattern)

                    # convert value to one the main types
                    item["set_value"] = SNMP.TYPE[item["value_type"]](set_value)

                result[key] = item
        
        return result
    
    @staticmethod
    def _check_errors(errorIndication, errorStatus, errorIndex, varBinds, payload: PayloadData) -> None:
        if errorIndication:
            raise SNMPTransportError(errorIndication)
        
        if errorStatus:
            raise SNMPProtocolError(str(errorStatus), int(errorIndex), list(payload.keys()))
    
    @staticmethod
    def _convert_result_value(value: SnmpValue, data: str) -> str | int | tuple[int]:
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
    
    # split octet string with reserved bytes spaces to tuple
    @staticmethod
    def _split_octet_by_pattern(octet_string: str, pattern: str) -> tuple[int]:
        bytes_string = bytes.fromhex(octet_string[2:])
        # format string, > is needed for big-endian bytes order
        fmt = ">" + "".join(SNMP.PATTERN_MAPPING[bytes_count] for bytes_count in pattern)
        # unpack bytes to tuple using struct and keeping bytes spaces
        return struct.unpack(fmt, bytes_string)

    # build octet string with reserved bytes spaces from tuple
    @staticmethod
    def _build_octet_by_pattern(data_tuple: tuple[int], pattern: str) -> bytes:
        # format string, > is needed for big-endian bytes order
        fmt = ">" + "".join(SNMP.PATTERN_MAPPING[bytes_count] for bytes_count in pattern)
        # form bytes from tuple using struct and keeping bytes spaces
        return struct.pack(fmt, *data_tuple)
    
    @staticmethod
    def _convert_octet_string_into_mac(octet_string: str) -> str:
        return "-".join([octet_string[2*i:2*i+2].upper() for i in range(1, 7)])

    @abstractmethod
    def _render_get_set_oid(self, oid: str, **params) -> str:
        pass

    @staticmethod
    def _render_bulk_walk_oid(oid: str) -> str:
        return re.sub(r"\.{.*", "", oid)