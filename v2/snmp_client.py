#!/usr/bin/python3
import asyncio
import yaml
import struct
import re
from typing import Any, Self
from collections import defaultdict
from abc import ABC, abstractmethod
from pprint import pprint
from copy import deepcopy
from icmplib import ping
from pysnmp.hlapi.v3arch.asyncio import *
from pyasn1.type.univ import ObjectIdentifier
from pysnmp.proto.rfc1902 import OctetString, Integer, IpAddress
from const import SNMPRequestType, SNMP
from snmp_exceptions import *

# standard request data is dict with any value type
type RequestData = dict[str, Any]
# standard response data can have int key type
type ResponseData = dict[str | int, Any]
# standard payload data for get/set request
type PayloadData = dict[str, dict[str, Any]]
# association of snmp value types that can be got
type SnmpValue = ObjectIdentifier | OctetString | Integer | IpAddress

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
        task_oid = asyncio.create_task(self._get(self._config["system"], ["private_oid"], skip_init=True))
        task_description = asyncio.create_task(self._get(self._config["system"], ["description"], skip_init=True))
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
    
    async def _execute_snmp(
                self,
                request_type: SNMPRequestType,   # type of snmp request
                config_fragment: dict[str, Any],   # one of specified oid groups
                include_params: list[str] | dict[str, Any],   # parameters, optionally with values
                oid_vars: dict[str, Any] | None = None,   # variables to substitute into oids
                skip_init: bool = False   # flag for marking requests without pre-initialization
            ) -> dict[str, Any] | list[tuple[str, Any]]:
        # if it's not one of the identifying requests, check initialization
        if not skip_init:
            await self._initialize()

        # render payload with params and oids by common method
        payload = SNMPClient._compose_request_payload(request_type, config_fragment, include_params, oid_vars)

        # for bulk_walk requests
        if request_type == SNMPRequestType.BULK_WALK:
            # get the first params' data (cause it's only one param)
            param_data = next(iter(payload.values()))

            # create oid object
            oid_object = ObjectType(ObjectIdentity(param_data["oid"]))

            results = []

            # walk through all bulk_walk blocks of oids to collect values
            async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
                self._engine,
                self._read_community,
                self._transport,
                self._context,
                0, self._max_repetitions,
                oid_object,
                lexicographicMode=False
            ):
                # handle errors
                try:
                    SNMPClient._check_errors(errorIndication, errorStatus, errorIndex, varBinds, payload)
                except SNMPTransportError:
                    raise
                except SNMPProtocolError:
                    raise
                
                # for each oid - value pair
                for varBind in varBinds:
                    oid = str(varBind[0])
                    # convert value
                    value = SNMPClient._convert_result_value(varBind[1], param_data)
                    # write oid and value
                    results.append((oid, value))
            
            # [(oid, value), ...]
            return results
        
        # for get requests, form simple oid objects, use read community
        if request_type == SNMPRequestType.GET:
            oid_objects = [ObjectType(ObjectIdentity(request["oid"])) for request in payload.values()]
            cmd = get_cmd
            community = self._read_community
        
        # for set requests, form oid objects with set values, use write community
        else:
            oid_objects = [ObjectType(ObjectIdentity(request["oid"]), request["set_value"]) for request in payload.values()]
            cmd = set_cmd
            community = self._write_community
        
        # perform request using selected command and community
        errorIndication, errorStatus, errorIndex, varBinds = await cmd(
            self._engine,
            community,
            self._transport,
            self._context,
            *oid_objects
        )
        
        # handle errors
        try:
            SNMPClient._check_errors(errorIndication, errorStatus, errorIndex, varBinds, payload)
        except SNMPTransportError:
            raise
        except SNMPProtocolError:
            raise
        
        results = {}

        # for each value, convert it and write with the param name
        for (command_name, data), varBind in zip(payload.items(), varBinds):
            results[command_name] = SNMPClient._convert_result_value(varBind[1], data)
        
        # {param: value, ...}
        return results

    # snmp get request
    async def _get(
                self,
                config_fragment: dict[str, Any],   # one of specified oid groups
                include_params: dict[str, Any],   # parameters with values
                oid_vars: dict[str, Any] | None = None,   # variables to substitute into oids
                skip_init: bool = False   # flag for marking requests without pre-initialization
            ) -> dict[str, Any]:
        # use common method and return results dict
        return await self._execute_snmp(SNMPRequestType.GET, config_fragment, include_params, oid_vars, skip_init)

    # snmp set request
    async def _set(
                self,
                config_fragment: dict[str, Any],   # one of specified oid groups
                include_params: dict[str, Any],   # parameters with values
                oid_vars: dict[str, Any] | None = None   # variables to substitute into oids
            ) -> dict[str, Any]:
        # use common method and return results dict, usually reflecting set values
        return await self._execute_snmp(SNMPRequestType.SET, config_fragment, include_params, oid_vars)

    # snmp bulk_walk request
    async def _bulk_walk(
                self,
                config_fragment: dict[str, Any],   # one of specified oid groups
                include_params: list[str]   # list of parameter names
            ) -> list[tuple[str, Any]]:
        # use common method and return results list with pairs (oid, value)
        return await self._execute_snmp(SNMPRequestType.BULK_WALK, config_fragment, include_params)

    # get available mibs by private switch oid
    async def scan_available_mibs(self) -> ResponseData:
        # standard mib scanning oid returns only mib names
        results = set()
        
        # walk through all values
        for _, desciption in await self._bulk_walk(self._config["system"], ["standard_mib"]):
            results.add(desciption)
        
        # return set of mib names
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
    def _compose_request_payload(
                request_type: SNMPRequestType,   # type of snmp request
                config_fragment: dict[str, Any],   # one of specified oid groups
                include_params: list[str] | dict[str, Any],   # parameters, optionally with values
                oid_vars: dict[str, Any] | None = None   # variables to substitute into oids
            ) -> PayloadData:
        result = {}

        # for config fragment, include only specified oids
        for key in include_params:
            if key in config_fragment:
                # deepcopy is needed for keeping nested structure safe
                item: dict[str, Any] = deepcopy(config_fragment[key])
                
                # for bulk walk requests, payload includes only one oid
                if request_type == SNMPRequestType.BULK_WALK:
                    # exclude any indices from oid to get dry oid for walking
                    item["oid"] = SNMPClient._render_bulk_walk_oid(item["oid"])

                # for get/set requests, make substitutions in oid if it's needed
                elif oid_vars is not None:
                    item["oid"] = SNMPClient._render_get_set_oid(item["oid"], oid_vars)

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

    # ender any oid using vars dict to substitute variables and indices if has any
    @staticmethod
    def _render_get_set_oid(oid: str, oid_vars: dict[str, Any]) -> str:
        return oid.format(**oid_vars)

    @staticmethod
    def _render_bulk_walk_oid(oid: str) -> str:
        return re.sub(r"\.{.*", "", oid)

    # parsing last index is necessary for gathering data by inner indices while bulk walking
    @staticmethod
    def _parse_last_index(oid: str) -> tuple[str, int]:
        parts = oid.rpartition(".")
        # return base part in integer index
        return parts[0], int(parts[2])