#!/usr/bin/python3
import asyncio
import struct
from typing import override, Any, Callable
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from time import perf_counter
from pysnmp.hlapi.v3arch.asyncio import *
from snmp_client import SNMPClient
from const import SNMP
from snmp_exceptions import *

type RequestData = dict[str, Any]
type ResponseData = dict[str | int, Any]

class L2SwitchClient(SNMPClient):
    _port: int
    _ports_count: int
    _is_gigabit_ethernet_port: bool
    _is_combo_port: bool
    _check_combo_fiber_port_lock: asyncio.Lock
    _is_combo_fiber_port: bool | None
    _is_fiber_port: bool
    _switch_oids_config: dict[str, Any]
    
    def __init__(self, ipaddress: str, port: int) -> None:
        super().__init__(ipaddress)
        self._port = port
    
    @override
    def _post_init(self) -> None:
        self._ports_count = self._config["models"][self._model]["ports_count"]
        self._model = self._config["models"][self._model]["base_model"]

        self._is_gigabit_ethernet_port = self._port >= self._config["models"][self._model]["first_gigabit_port"]
        self._is_combo_port = self._port in self._config["models"][self._model]["combo_ports"]
        self._check_combo_fiber_port_lock = asyncio.Lock()
        self._is_combo_fiber_port = None
        self._is_fiber_port = self._port in self._config["models"][self._model]["fiber_ports"]

        self._switch_oids_config = self._config["models"][self._model]["oids"]
    
    ### MIB MODULES ###

    async def scan_available_mibs(self) -> ResponseData:
        results = defaultdict(dict)
        
        for oid, desciption in await self._bulk_walk(self._switch_oids_config["private_mib_modules"]["description"]):
            results[L2SwitchClient._parse_last_index(oid)[1]]["desciption"] = desciption

        for oid, version in await self._bulk_walk(self._switch_oids_config["private_mib_modules"]["version"]):
            results[L2SwitchClient._parse_last_index(oid)[1]]["version"] = version

        for oid, value_type in await self._bulk_walk(self._switch_oids_config["private_mib_modules"]["value_type"]):
            results[L2SwitchClient._parse_last_index(oid)[1]]["value_type"] = value_type
        
        return {value["desciption"]: {"version": value["version"], "value_type": value["value_type"]} for value in results.values()}

    ### SWITCH MANAGEMENT AND INFO ###

    async def _get_switch_data(self, include_oids: list[str]) -> ResponseData:
        return await self._get(SNMPClient._filter_request_config(self._switch_oids_config["switch"], include_oids))
    
    async def perform_system_reboot(self, request: RequestData) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["switch"], ["system_reboot_mode"])
        
        for param, data in payload.items():
            data["set_value"] = request[param]
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            await self._action_after_system_reboot(request["system_reboot_mode"])
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def perform_save(self, request: RequestData) -> SNMPResponseCode:
        action_payload = SNMPClient._filter_request_config(self._switch_oids_config["switch"], ["save_action"])
        action_payload["save_action"]["set_value"] = request["save_action"]
        
        try:
            result = await self._set(action_payload)
            await self._check_save_status()
        except SNMPTransportError as err:
            if request["save_action"] in {"config_id1", "config_id2", "all"}:
                await self._check_save_status()
            else:
                return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def _check_save_status(self) -> None:
        status_payload = SNMPClient._filter_request_config(self._switch_oids_config["switch"], ["save_status"])
        status = await self._get(status_payload)
        while status["save_status"] not in {"other", "completed"}:
            status = await self._get(status_payload)

    async def get_network_parameters(self) -> ResponseData:
        include_oids = ["ip", "mask", "default_gateway", "management_vlan_id"]
        return await self._get_switch_data(include_oids)
    
    async def set_network_parameters(self, request: RequestData) -> SNMPResponseCode:
        include_oids = list(request.keys())
        payload = SNMPClient._filter_request_config(self._switch_oids_config["switch"], include_oids)
        
        for param, data in payload.items():
            data["set_value"] = request[param]
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            if "ip" in request:
                await self._action_after_ip_address_change(request["ip"])
            elif "default_gateway" in request or "management_vlan_id" in request:
                pass
            else:
                return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    async def get_mac_address(self) -> ResponseData:
        return await self._get_switch_data(["mac_address"])
    
    async def get_ports_number(self) -> ResponseData:
        return await self._get_switch_data(["ports_number"])

    async def get_current_time(self) -> ResponseData:
        result = await self._get_switch_data(["current_time"])
        return {"current_time": datetime(*result["current_time"])}
    
    async def set_current_time(self, request: RequestData) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["switch"], ["current_time"])
        
        for param, data in payload.items():
            set_value: datetime = request[param]
            set_value = L2SwitchClient._build_octet_by_pattern(set_value.timetuple()[:6] + (set_value.microsecond // 100000,),
                                                               data["bytes_pattern"])
            data["set_value"] = set_value
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            elif err.status == "undoFailed":
                # forbidden error is usually caused when sntp is enabled
                return SNMPResponseCode.FORBIDDEN
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    async def get_cpu_utilization(self) -> ResponseData:
        include_oids = ["cpu_utilization_5sec", "cpu_utilization_1min", "cpu_utilization_5min"]
        results = await self._get_switch_data(include_oids)
        return {key.removeprefix("cpu_utilization_"): value for key, value in results.items()}

    async def get_dram_utilization(self) -> ResponseData:
        include_oids = ["dram_total", "dram_used", "dram_utilization"]
        results = await self._get_switch_data(include_oids)
        return {key.removeprefix("dram_"): value for key, value in results.items()}
    
    ### TRUSTED HOST ###

    async def get_trusted_hosts(self) -> ResponseData:
        results = defaultdict(dict)
        
        for oid, ip in await self._bulk_walk(self._switch_oids_config["trusted_host"]["ip"]):
            host_index = L2SwitchClient._parse_last_index(oid)[1]
            # consider 24-bit mask by default
            results[host_index] = {"ip": ip, "mask": "255.255.255.0"}
        
        for oid, mask in await self._bulk_walk(self._switch_oids_config["trusted_host"]["mask"]):
            host_index = L2SwitchClient._parse_last_index(oid)[1]
            # consider 24-bit mask by default
            results[host_index]["mask"] = mask
        
        return results
    
    async def _find_first_free_host_index(self) -> int:
        occupied_indices = set()

        for oid, _ in await self._bulk_walk(self._switch_oids_config["trusted_host"]["ip"]):
            host_index = L2SwitchClient._parse_last_index(oid)[1]
            occupied_indices.add(host_index)
        
        current = 1
        while current in occupied_indices:
            current += 1
        
        return current

    async def add_trusted_host(self, request: RequestData) -> SNMPResponseCode:
        include_oids = ["ip", "mask", "entry_status"]
        payload = SNMPClient._filter_request_config(self._switch_oids_config["trusted_host"], include_oids)
        
        payload["ip"]["set_value"] = request["ip"]
        payload["mask"]["set_value"] = request["mask"]
        payload["entry_status"]["set_value"] = "create_and_go"

        # it's important to find free index to avoid errors
        host_index = await self._find_first_free_host_index()
        for oid in include_oids:
            payload[oid]["params"] = {"host_index": host_index}

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def delete_trusted_host(self, request: RequestData) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["trusted_host"], ["entry_status"])
        
        payload["entry_status"]["params"] = {"host_index": request["host_index"]}
        payload["entry_status"]["set_value"] = "destroy"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def delete_all_trusted_host(self) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["trusted_host"], ["delete_all"])
        payload["delete_all"]["set_value"] = "start"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### ACL ###

    # masks getting
    async def _get_acl_mask(self, acl_type: str, attributes_to_check: list[str],
                            check_profile_id: Callable[[dict[str, str]], dict[str, Any]]) -> ResponseData:
        attributes_to_check = [f"{acl_type}_mask_{attribute}" for attribute in attributes_to_check]
        pre_results = defaultdict(dict)
        
        for attribute in attributes_to_check:
            for oid, value in await self._bulk_walk(self._switch_oids_config["acl"][attribute]):
                profile_id = L2SwitchClient._parse_last_index(oid)[1]
                pre_results[profile_id][attribute] = value
        
        results = {}

        for profile_id, profile_id_config in pre_results.items():
            temp_profile_id_config = {}

            for attribute in attributes_to_check:
                # if any attribute was not found, skip profile
                if attribute not in profile_id_config:
                    break

                temp_profile_id_config[attribute.removeprefix(f"{acl_type}_mask_")] = profile_id_config[attribute]
            
            else:
                results[profile_id] = {
                    "type": acl_type,
                    "mask_management": check_profile_id(temp_profile_id_config)
                }

        return results

    async def _get_acl_ethernet_mask(self) -> ResponseData:
        def check_profile_id(profile_id_config: dict[str, str]) -> dict[str, Any]:
            # for zero/any source/destination mac masks, leave them empty
            if profile_id_config["source_mac_mask"] == SNMP.ZERO_MAC_ADDRESS:
                profile_id_config["source_mac_mask"] = ""
            if profile_id_config["destination_mac_mask"] == SNMP.ZERO_MAC_ADDRESS:
                profile_id_config["destination_mac_mask"] = ""
            
            source_mac_false_check_state = True \
                if profile_id_config["mac_mask_state"] == "source_mac" and profile_id_config["source_mac_mask"] == "" \
                else False

            return {
                **{key: profile_id_config[key] for key in filter_attributes},
                "source_mac_false_check_state": source_mac_false_check_state,
                "owner": profile_id_config["owner"]
            }

        acl_type = "ethernet"
        filter_attributes = ["use_vlan", "mac_mask_state", "source_mac_mask",
                             "destination_mac_mask", "use_802_1p", "use_ethernet_type"]
        attributes_to_check = [*filter_attributes, "owner"]

        return await self._get_acl_mask(acl_type, attributes_to_check, check_profile_id)

    async def _get_acl_packet_content_mask(self) -> ResponseData:
        def check_profile_id(profile_id_config: dict[str, str]) -> dict[str, Any]:
            general_mask = "0x" + "".join(profile_id_config[mask][2:] for mask in masks)
            fully_inspected_bytes = L2SwitchClient._parse_acl_packet_content_fully_inspected_bytes(general_mask[2:])
            ipv4_arp_check_state = L2SwitchClient._discover_acl_packet_content_ipv4_arp_check_state(fully_inspected_bytes)

            return {
                "general_mask": general_mask,
                "fully_inspected_bytes": fully_inspected_bytes,
                "ipv4_arp_check_state": ipv4_arp_check_state,
                "owner": profile_id_config["owner"]
            }
        
        acl_type = "packet_content"
        masks = ["offset_0_15", "offset_16_31", "offset_32_47", "offset_48_63", "offset_64_79"]
        attributes_to_check = [*masks, "owner"]

        return await self._get_acl_mask(acl_type, attributes_to_check, check_profile_id)

    # rules getting
    async def _get_acl_rule(self, acl_type: str, attributes_to_check: list[str],
                            convert_value: Callable[[dict[str, Any], str], Any],
                            transform_access_id_config: Callable[[dict[str, Any]], dict[str, Any]]) -> ResponseData:
        attributes_to_check = [f"{acl_type}_rule_{attribute}" for attribute in attributes_to_check]
        pre_results = defaultdict(lambda: defaultdict(dict))
        
        for attribute in attributes_to_check:
            for oid, value in await self._bulk_walk(self._switch_oids_config["acl"][attribute]):
                cut_oid, access_id = L2SwitchClient._parse_last_index(oid)
                profile_id = L2SwitchClient._parse_last_index(cut_oid)[1]
                pre_results[profile_id][access_id][attribute] = value
        
        results = {}

        for profile_id, profile_id_config in pre_results.items():
            results[profile_id] = {
                "type": acl_type,
                "rule_management": defaultdict(dict)
            }
            rule_management = results[profile_id]["rule_management"]

            for access_id, access_id_config in profile_id_config.items():
                temp_access_id_config = {}

                for attribute in attributes_to_check:
                    # if any attribute was not found, skip rule
                    if attribute not in access_id_config:
                        break

                    temp_access_id_config[attribute.removeprefix(f"{acl_type}_rule_")] = convert_value(access_id_config, attribute)
                else:
                    rule_management[access_id] = transform_access_id_config(temp_access_id_config)
        
        # if all access id rules are skipped in one profile id, keep the profile id because it should have at least correct mask
        return results

    async def _get_acl_ethernet_rule(self) -> ResponseData:
        def convert_value(access_id_config: dict[str, Any], attribute: str) -> Any:
            value = access_id_config[attribute]

            match attribute.removeprefix(f"{acl_type}_rule_"):
                # when vlan name is not stated, the value is 64-byte zero string, miss it
                case "vlan_name":
                    if value == SNMP.ZERO_VLAN_NAME:
                        value = ""
                # miss zero/any mac address values
                case "source_mac" | "destination_mac":
                    if value == SNMP.ZERO_MAC_ADDRESS:
                        value = ""
                # 802.1p default -1 becomes "" for unified form
                case "check_802_1p":
                    if value == -1:
                        value = ""
                # miss zero/any ethernet type value
                case "ethernet_type":
                    if value == SNMP.ZERO_ETHERNET_TYPE:
                        value = ""
                # for ports, get the portlist
                case "ports":
                    value = L2SwitchClient._parse_assigned_ports_from_hex(value, self._ports_count)

            return value
        
        def transform_access_id_config(access_id_config: dict[str, Any]) -> dict[str, Any]:
            # access id rule counts every frame if all filter attributes have default values
            any_frame = all(access_id_config[key] == "" for key in filter_attributes)

            return {
                **{key: access_id_config[key] for key in filter_attributes},
                "any_frame": any_frame,
                **{key: access_id_config[key] for key in secondary_attributes}
            }

        acl_type = "ethernet"
        filter_attributes = ["vlan_name", "source_mac", "destination_mac", "check_802_1p", "ethernet_type"]
        secondary_attributes = ["enable_local_priority", "local_priority", "permit", "ports", "owner", "rx_rate"]
        attributes_to_check = filter_attributes + secondary_attributes
        
        return await self._get_acl_rule(acl_type, attributes_to_check, convert_value, transform_access_id_config)

    async def _get_acl_packet_content_rule(self) -> ResponseData:
        def convert_value(access_id_config: dict[str, Any], attribute: str) -> Any:
            value = access_id_config[attribute]

            match attribute.removeprefix(f"{acl_type}_rule_"):
                # for ports, get the portlist
                case "ports":
                    value = L2SwitchClient._parse_assigned_ports_from_hex(value, self._ports_count)
            
            return value
        
        def transform_access_id_config(access_id_config: dict[str, Any]) -> dict[str, Any]:
            offset_chunks = {}
            
            for ind in range(1, 6):
                index, mask, data = [access_id_config.pop(f"offset_{attribute}_{ind}")
                                     for attribute in ["index", "mask", "data"]]
                # keep only those offset chunks that have not default value
                if mask != SNMP.ZERO_OFFSET_CHUNK:
                    fully_inspected_bytes = L2SwitchClient._parse_acl_packet_content_fully_inspected_bytes("00" * index + mask[2:])
                    offset_chunks[index] = {"mask": mask,
                                            "data": data,
                                            "fully_inspected_bytes": fully_inspected_bytes}
            
            offset_chunks = dict(sorted(offset_chunks.items()))
            mask, data = "", ""
            fully_inspected_bytes = set()
            ipv4_arp_check_state = "none"
            source_ip = ""

            # access id rule is considered wrong if any other chunk doesn't have default value
            if len(offset_chunks) == 1:
                main_offset_chunk = next(iter(offset_chunks.values()))
                mask, data, fully_inspected_bytes = (
                    main_offset_chunk[key] for key in ("mask", "data", "fully_inspected_bytes")
                )

                ipv4_arp_check_state = L2SwitchClient._discover_acl_packet_content_ipv4_arp_check_state(fully_inspected_bytes)
                # source ip will be filled only if access id rule checks ipv4/arp source ip with real value
                if ipv4_arp_check_state in {"ipv4", "arp"} and data != SNMP.ZERO_OFFSET_CHUNK:
                    source_ip = L2SwitchClient._parse_acl_chunk_to_ip(data)
            
            return {
                "offsets": offset_chunks,
                "main_mask": mask,
                "main_data": data,
                "fully_inspected_bytes": fully_inspected_bytes,
                "ipv4_arp_check_state": ipv4_arp_check_state,
                "source_ip": source_ip,
                **{key: access_id_config[key] for key in secondary_attributes}
            }

        acl_type = "packet_content"
        filter_attributes = [
            f"offset_{attribute}_{ind}"
            for ind in range(1, 6)
            for attribute in ["index", "mask", "data"]
        ]
        secondary_attributes = ["enable_local_priority", "local_priority", "permit", "ports", "rx_rate"]
        attributes_to_check = filter_attributes + secondary_attributes
        
        return await self._get_acl_rule(acl_type, attributes_to_check, convert_value, transform_access_id_config)

    # overall getting
    async def _merge_acl_mask_and_rule(self, mask: dict[int, dict[str, Any]], rule: dict[int, dict[str, Any]]) -> ResponseData:
        for profile_id, profile_id_config in mask.items():
            if profile_id in rule:
                profile_id_config.update(rule[profile_id])
        
        return mask
    
    async def get_acl_ethernet(self) -> ResponseData:
        mask = await self._get_acl_ethernet_mask()
        rule = await self._get_acl_ethernet_rule()
        
        return await self._merge_acl_mask_and_rule(mask, rule)
    
    async def get_acl_packet_content(self) -> ResponseData:
        mask = await self._get_acl_packet_content_mask()
        rule = await self._get_acl_packet_content_rule()
        
        return await self._merge_acl_mask_and_rule(mask, rule)
    
    async def get_acl_all(self) -> ResponseData:
        ethernet = await self.get_acl_ethernet()
        packet_content = await self.get_acl_packet_content()

        return dict(sorted({**ethernet, **packet_content}.items()))
    
    # for port getting
    async def get_acl_for_port(self) -> ResponseData:
        acl_table = await self.get_acl_all()
        result = {}

        for profile_id, profile_id_config in acl_table.items():
            rule_management: dict[int, dict[str, Any]] = profile_id_config["rule_management"]
            for access_id, access_id_config in rule_management.items():
                if self._port in rule_management[access_id]["ports"]:
                    if profile_id not in result:
                        result[profile_id] = {
                            "type": profile_id_config["type"],
                            "mask_management": profile_id_config["mask_management"],
                            "rule_management": {}
                        }
                    result[profile_id]["rule_management"][access_id] = access_id_config
        
        return result
    
    # ethernet mask setting
    async def _get_acl_ethernet_mask_entry_status(self, profile_id: int) -> ResponseData:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["acl"], ["ethernet_mask_entry_status"])
        payload["ethernet_mask_entry_status"]["params"] = {"profile_id": profile_id}
        return (await self._get(payload))["ethernet_mask_entry_status"]
    
    async def create_acl_ethernet_mask(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_acl_ethernet_mask_entry_status(request["profile_id"]) == "active":
            return SNMPResponseCode.INVALID_DATA
        
        # mac_mask_state oid is necessary for identifying any mac mask
        if "source_mac_mask" in request:
            if "destination_mac_mask" in request:
                mac_mask_state = "destination_source_mac"
            else:
                mac_mask_state = "source_mac"
        elif "destination_mac_mask" in request:
            mac_mask_state = "destination_mac"
        else:
            mac_mask_state = "other"
        
        base_prefix = "ethernet_mask_"
        include_oids = [f"{base_prefix}{param}" for param in request.keys() if param != "profile_id"]
        if mac_mask_state != "other":
            include_oids.insert(0, f"{base_prefix}mac_mask_state")
        include_oids.append(f"{base_prefix}entry_status")
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["acl"], include_oids)
        for param, data in payload.items():
            param = param.removeprefix(base_prefix)
            match param:
                case "entry_status":
                    set_value = "create_and_go"
                case "mac_mask_state":
                    set_value = mac_mask_state
                case _:
                    set_value = request[param]
            data["set_value"] = set_value
            data["params"] = {"profile_id": request["profile_id"]}

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "notWritable":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def delete_acl_ethernet_mask(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_acl_ethernet_mask_entry_status(request["profile_id"]) is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["acl"], ["ethernet_mask_entry_status"])
        payload["ethernet_mask_entry_status"]["params"] = {"profile_id": request["profile_id"]}
        payload["ethernet_mask_entry_status"]["set_value"] = "destroy"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "notWritable":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # ethernet rule setting
    async def _get_acl_ethernet_rule_entry_status(self, profile_id: int, access_id: int) -> ResponseData:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["acl"], ["ethernet_rule_entry_status"])
        payload["ethernet_rule_entry_status"]["params"] = {"profile_id": profile_id, "access_id": access_id}
        return (await self._get(payload))["ethernet_rule_entry_status"]
    
    async def add_acl_ethernet_rule(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_acl_ethernet_mask_entry_status(request["profile_id"]) is None or \
                await self._get_acl_ethernet_rule_entry_status(request["profile_id"], request["access_id"]) == "active":
            return SNMPResponseCode.INVALID_DATA
        
        base_prefix = "ethernet_rule_"
        include_oids = [f"{base_prefix}{param}"
                        for param in request.keys()
                        if param not in {"profile_id", "access_id"}]
        
        # enable_local_priority oid is necessary for local_priority oid
        if "local_priority" in request:
            include_oids.insert(0, f"{base_prefix}enable_local_priority")
        include_oids.append(f"{base_prefix}entry_status")
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["acl"], include_oids)
        for param, data in payload.items():
            param = param.removeprefix(base_prefix)
            match param:
                case "entry_status":
                    set_value = "create_and_go"
                case "enable_local_priority":
                    set_value = "enabled"
                case "ports":
                    set_value = L2SwitchClient._combine_assigned_ports_to_hex(request[param])
                case _:
                    set_value = request[param]
            data["set_value"] = set_value
            data["params"] = {"profile_id": request["profile_id"], "access_id": request["access_id"]}

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def delete_acl_ethernet_rule(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_acl_ethernet_mask_entry_status(request["profile_id"]) is None or \
                await self._get_acl_ethernet_rule_entry_status(request["profile_id"], request["access_id"]) is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["acl"], ["ethernet_rule_entry_status"])
        payload["ethernet_rule_entry_status"]["params"] = {"profile_id": request["profile_id"],
                                                           "access_id": request["access_id"]}
        payload["ethernet_rule_entry_status"]["set_value"] = "destroy"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "notWritable":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # packet content mask setting
    async def _get_acl_packet_content_mask_entry_status(self, profile_id: int) -> ResponseData:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["acl"], ["packet_content_mask_entry_status"])
        payload["packet_content_mask_entry_status"]["params"] = {"profile_id": profile_id}
        return (await self._get(payload))["packet_content_mask_entry_status"]
    
    async def create_acl_packet_content_mask(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_acl_packet_content_mask_entry_status(request["profile_id"]) == "active":
            return SNMPResponseCode.INVALID_DATA
        
        base_prefix = "packet_content_mask_"
        include_oids = [f"{base_prefix}{param}" for param in request.keys() if param != "profile_id"]
        include_oids.append(f"{base_prefix}entry_status")
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["acl"], include_oids)
        for param, data in payload.items():
            param = param.removeprefix(base_prefix)
            match param:
                case "entry_status":
                    set_value = "create_and_go"
                case _:
                    set_value = request[param]
            data["set_value"] = set_value
            data["params"] = {"profile_id": request["profile_id"]}

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            print(err)
            if err.status == "notWritable":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def delete_acl_packet_content_mask(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_acl_packet_content_mask_entry_status(request["profile_id"]) is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["acl"], ["packet_content_mask_entry_status"])
        payload["packet_content_mask_entry_status"]["params"] = {"profile_id": request["profile_id"]}
        payload["packet_content_mask_entry_status"]["set_value"] = "destroy"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "notWritable":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### VLAN ###

    async def get_vlan_static_table(self) -> defaultdict[int, dict[str, Any]]:
        results = defaultdict(dict)
        
        for oid, vlan_name in await self._bulk_walk(self._switch_oids_config["vlan"]["name"]):
            vlan_id = L2SwitchClient._parse_last_index(oid)[1]
            # consider default empty sets for tagged/untagged ports
            results[vlan_id] = {"vlan_name": vlan_name, "tagged_ports": set(), "untagged_ports": set()}
        
        # tagged
        for oid, octet_string in await self._bulk_walk(self._switch_oids_config["vlan"]["egress_ports"]):
            vlan_id = L2SwitchClient._parse_last_index(oid)[1]
            portlist = L2SwitchClient._parse_assigned_ports_from_hex(octet_string, self._ports_count)
            # for first discovered vlan, consider vlan name is the same as vlan id
            if vlan_id not in results:
                results[vlan_id] = {"vlan_name": str(vlan_id), "untagged_ports": set()}
            results[vlan_id]["tagged_ports"] = portlist
        
        # untagged
        for oid, octet_string in await self._bulk_walk(self._switch_oids_config["vlan"]["untagged_ports"]):
            vlan_id = L2SwitchClient._parse_last_index(oid)[1]
            portlist = L2SwitchClient._parse_assigned_ports_from_hex(octet_string, self._ports_count)
            # for first discovered vlan, consider vlan name is the same as vlan id
            if vlan_id not in results:
                results[vlan_id] = {"vlan_name": str(vlan_id), "tagged_ports": set(), "untagged_ports": portlist}
            results[vlan_id]["untagged_ports"] = portlist
            results[vlan_id]["tagged_ports"] -= results[vlan_id]["untagged_ports"]
        
        return results
    
    # get vlan static table for specified vlan
    async def _get_exact_vlan_table(self, vlan_id: int) -> ResponseData:
        vlan_static_table = await self.get_vlan_static_table()
        if vlan_id not in vlan_static_table:
            return {}
        return {vlan_id: vlan_static_table[vlan_id]}
    
    async def get_vlan_on_port(self) -> ResponseData:
        vlan_static_table = await self.get_vlan_static_table()
        result = defaultdict(dict)

        for vlan_id, vlan_info in vlan_static_table.items():
            vlan_name =  vlan_info["vlan_name"]
            if self._port in vlan_info["tagged_ports"]:
                result["tagged"][vlan_id] = vlan_name
            elif self._port in vlan_info["untagged_ports"]:
                result["untagged"][vlan_id] = vlan_name

        return result
    
    # check that vlan with this vlan_id exists, necessary for delete vlan, add/delete vlan on ports
    async def _get_vlan_entry_status(self, vlan_id: int) -> ResponseData:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["entry_status"])
        payload["entry_status"]["params"] = {"vlan_id": vlan_id}
        return (await self._get(payload))["entry_status"]
    
    async def create_vlan(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_vlan_entry_status(request["vlan_id"]) == "active":
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["name", "entry_status"])
        for command in payload.values():
            command["params"] = {"vlan_id": request["vlan_id"]}
        
        payload["name"]["set_value"] = request["vlan_name"]
        payload["entry_status"]["set_value"] = "create_and_go"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "commitFailed":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def rename_vlan(self, request: RequestData) -> SNMPResponseCode:
        """
        WARNING: this way of changing VLAN's name is not stable and disrupts users' connections.
        """
        old_vlan_data = await self._get_exact_vlan_table(request["vlan_id"])

        response = await self.delete_vlan({"vlan_id": request["vlan_id"]})
        if response != SNMPResponseCode.SUCCESS:
            return response
        
        response = await self.create_vlan(request)
        if response != SNMPResponseCode.SUCCESS:
            return response
        
        for status in ["tagged", "untagged"]:
            response = await self.add_vlan_on_ports({"vlan_id": request["vlan_id"],
                                                     "portlist": old_vlan_data[request["vlan_id"]][f"{status}_ports"],
                                                     "status": status})
            if response != SNMPResponseCode.SUCCESS:
                return response
        
        return response

    async def delete_vlan(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_vlan_entry_status(request["vlan_id"]) is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["entry_status"])
        payload["entry_status"]["params"] = {"vlan_id": request["vlan_id"]}
        payload["entry_status"]["set_value"] = "destroy"
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def _get_ports_with_vlan_status(self, vlan_id: int, status: str) -> set[int]:
        request_name = L2SwitchClient._get_request_name_for_vlan_status(status)
        if request_name is None:
            return SNMPResponseCode.INVALID_DATA

        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], [request_name])
        payload[request_name]["params"] = {"vlan_id": vlan_id}

        result = await self._get(payload)
        ports = L2SwitchClient._parse_assigned_ports_from_hex(result[request_name], self._ports_count)
        return ports
    
    async def add_vlan_on_ports(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_vlan_entry_status(request["vlan_id"]) is None:
            return SNMPResponseCode.INVALID_DATA

        request_name = L2SwitchClient._get_request_name_for_vlan_status(request["status"])
        if request_name is None:
            return SNMPResponseCode.INVALID_DATA
        
        # for ports that were untagged, untagged + egress -> untagged
        portlist = request["portlist"] | await self._get_ports_with_vlan_status(request["vlan_id"], request["status"])
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], [request_name])
        payload[request_name]["params"] = {"vlan_id": request["vlan_id"]}
        payload[request_name]["set_value"] = L2SwitchClient._combine_assigned_ports_to_hex(portlist)
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "commitFailed":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def delete_vlan_from_ports(self, request: RequestData) -> SNMPResponseCode:
        if await self._get_vlan_entry_status(request["vlan_id"]) is None:
            return SNMPResponseCode.INVALID_DATA

        status = "tagged"
        portlist = await self._get_ports_with_vlan_status(request["vlan_id"], status) - request["portlist"]
        
        request_name = L2SwitchClient._get_request_name_for_vlan_status(status)
        if request_name is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], [request_name])
        payload[request_name]["params"] = {"vlan_id": request["vlan_id"]}
        payload[request_name]["set_value"] = L2SwitchClient._combine_assigned_ports_to_hex(portlist)
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### FDB ###

    async def get_fdb_table(self) -> defaultdict[int, dict[str, dict[str, Any]]]:
        results = defaultdict(dict)

        for oid, port in await self._bulk_walk(self._switch_oids_config["fdb"]["port"]):
            _, vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(oid)
            # default status is dynamic, so if mac's status won't be found it means it's dynamic
            results[vlan_id][mac] = {"port": port, "status": "dynamic"}

        for oid, status in await self._bulk_walk(self._switch_oids_config["fdb"]["status"]):
            _, vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(oid)
            if status not in {"invalid" , "self"}:
                status = "dynamic" if status == "learned" else "static"
            if mac in results[vlan_id]:   # if mac's port is unknown, don't count it
                results[vlan_id][mac]["status"] = status

        return results
    
    async def get_fdb_on_port(self) -> ResponseData:
        fdb_table = await self.get_fdb_table()
        result = defaultdict(dict)

        for vlan_id, mac_list in fdb_table.items():
            for mac, mac_info in mac_list.items():
                if mac_info["port"] == self._port and mac_info["status"] not in {"invalid" , "self"}:
                    result[mac][vlan_id] = {"status": mac_info["status"]}
        
        return result
    
    # clear fdb on port by turning on/off port security on port
    async def clear_fdb_on_port(self) -> SNMPResponseCode:
        result = await self.set_port_security_on_port({"admin_state": "enable"})
        if result != SNMPResponseCode.SUCCESS:
            return result
        return await self.set_port_security_on_port({"admin_state": "disable"})
    
    async def clear_fdb_all(self) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["fdb"], ["clear_all"])
        payload["clear_all"]["set_value"] = "start"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### FLOOD FDB ###

    async def get_flood_fdb(self) -> ResponseData:
        results = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["flood_fdb"], ["state"]))
        if results["state"] == "disabled":
            return results
        
        table = defaultdict(dict)
        
        for oid, status in await self._bulk_walk(self._switch_oids_config["flood_fdb"]["status"]):
            cut_oid, vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(oid)
            index = L2SwitchClient._parse_last_index(cut_oid)[1]
            table[index][mac] = {"vlan_id": vlan_id, "status": status}
        
        for oid, timestamp in await self._bulk_walk(self._switch_oids_config["flood_fdb"]["timestamp"]):
            cut_oid, vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(oid)
            index = L2SwitchClient._parse_last_index(cut_oid)[1]
            if index in table and mac in table[index]:   # if index or mac is unknown, don't count them
                table[index][mac]["timestamp"] = timestamp
        
        results["table"] = table
        return results
    
    async def set_flood_fdb(self, request: RequestData) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["flood_fdb"], ["state"])
        payload["state"]["set_value"] = request["state"]

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def clear_flood_fdb(self) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["flood_fdb"], ["clear"])
        payload["clear"]["set_value"] = "start"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### IPIF ###

    async def _get_ipif_name(self, if_index: int) -> ResponseData:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["ipif"], ["name"])
        payload["name"]["params"] = {"if_index": if_index}
        result = await self._get(payload)
        return result["name"]

    ### DHCP RELAY ###

    async def get_dhcp_relay(self) -> ResponseData:
        include_oids = ["state", "hop_count", "time_threshold",
                        "option82_state", "option82_check_state", "option82_policy", "option82_remote_id_type", "option82_remote_id"]
        results = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["dhcp_relay"], include_oids))

        results["ipif_servers"] = defaultdict(set)
        results["vlan_id_servers"] = defaultdict(set)

        for oid, interface_name in await self._bulk_walk(self._switch_oids_config["dhcp_relay"]["ipif_server"]):
            server_ip = L2SwitchClient._parse_ip_address_from_oid(oid)[1]
            results["ipif_servers"][interface_name].add(server_ip)
        
        # vlan id - servers logic will be implemented for other switch models

        return results
    
    async def set_dhcp_relay(self, request: RequestData) -> SNMPResponseCode:
        include_oids = list(request.keys())
        payload = SNMPClient._filter_request_config(self._switch_oids_config["dhcp_relay"], include_oids)

        for param, data in payload.items():
            data["set_value"] = request[param]

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def _manage_dhcp_servers_for_ipif(self, request: RequestData, mode: str) -> SNMPResponseCode:
        ipif_server_config = SNMPClient._filter_request_config(self._switch_oids_config["dhcp_relay"], ["ipif_server_entry_status"])["ipif_server_entry_status"]
        
        payload = {
            f"ipif_server_entry_status.{ipif_name}.{server}": {
                **ipif_server_config,
                "params": {"ipif_name": L2SwitchClient._convert_name_into_oid(ipif_name),
                           "dhcp_server": server},
                "set_value": mode
            }
            for ipif_name, servers in request["ipif_servers"].items() for server in servers
        }

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    async def add_dhcp_servers_for_ipif(self, request: RequestData) -> SNMPResponseCode:
        return await self._manage_dhcp_servers_for_ipif(request, "create_and_go")
    
    async def delete_dhcp_servers_for_ipif(self, request: RequestData) -> SNMPResponseCode:
        return await self._manage_dhcp_servers_for_ipif(request, "destroy")

    ### ARP ###

    async def get_arp_table(self) -> ResponseData:
        results = defaultdict(dict)
        ipif_names = {}

        for oid, mac in await self._bulk_walk(self._switch_oids_config["arp"]["mac_address"]):
            cut_oid, ip = L2SwitchClient._parse_ip_address_from_oid(oid)
            if_index = L2SwitchClient._parse_last_index(cut_oid)[1]
            if if_index not in ipif_names:
                ipif_names[if_index] = await self._get_ipif_name(if_index)
            results[ipif_names[if_index]][ip] = {"mac_address": mac, "status": "dynamic"}

        for oid, status in await self._bulk_walk(self._switch_oids_config["arp"]["status"]):
            cut_oid, ip = L2SwitchClient._parse_ip_address_from_oid(oid)
            if_index = L2SwitchClient._parse_last_index(cut_oid)[1]
            # if ip is unknown, don't count it
            if if_index in ipif_names and ip in results[ipif_names[if_index]] and status in {"other", "static"}:
                results[ipif_names[if_index]][ip]["status"] = "static"

        return results
    
    ### PORT MANAGEMENT AND INFO ###

    async def _check_fiber_combo_port(self) -> None:
        async with self._check_combo_fiber_port_lock:
            if self._is_combo_fiber_port is None:
                include_oids = ["link_status", "link_status_combo_fiber"]
                copper_fiber_statuses = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids))

                if copper_fiber_statuses["link_status"] != "link_pass" and copper_fiber_statuses["link_status_combo_fiber"] == "link_pass":
                    self._is_combo_fiber_port = True
                else:
                    self._is_combo_fiber_port = False

    async def _get_port_data(self, include_oids: list[str]) -> ResponseData:
        combo_fiber_suffix = None
        
        if self._is_combo_port:
            if self._is_combo_fiber_port is None and any([oid in self._switch_oids_config["port"]["combo_ports_oids"] for oid in include_oids]):
                await self._check_fiber_combo_port()
            
            if self._is_combo_fiber_port:
                combo_fiber_suffix = "_combo_fiber"
                include_oids = [oid + combo_fiber_suffix if oid in self._switch_oids_config["port"]["combo_ports_oids"] else oid for oid in include_oids]
        
        results = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids))
        
        if self._is_combo_fiber_port and combo_fiber_suffix is not None:
            results = {key.removesuffix(combo_fiber_suffix) if key.endswith(combo_fiber_suffix) else key: value for key, value in results.items()}
        
        return results

    async def get_port_status(self) -> ResponseData:
        include_oids = ["admin_state", "speed_duplex_settings", "link_status", "speed_duplex_status"]
        result = await self._get_port_data(include_oids)

        result["link_speed_duplex_status"] = "link_down" if result["link_status"] != "link_pass" else result["speed_duplex_status"]
        del result["link_status"]
        del result["speed_duplex_status"]

        return result

    async def get_port_management(self) -> ResponseData:
        include_oids = ["admin_state", "speed_duplex_settings", "flow_control", "address_learning", "mdix_state"]
        return await self._get_port_data(include_oids)
    
    async def set_port_management(self, request: RequestData) -> SNMPResponseCode:
        mdix_state_change = True if "mdix_state" in request else False   # mdix state change needs special logic and check
        
        include_oids = list(key for key in request.keys() if key != "mdix_state")   # other parameters by default
        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids)

        for param, data in payload.items():
            data["set_value"] = request[param]
        
        try:
            result = await self._set(payload)

            if mdix_state_change:
                mdix_payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], ["mdix_state"])
                mdix_payload["mdix_state"]["set_value"] = request["mdix_state"]
                try:
                    mdix_result = await self._set(mdix_payload)
                except SNMPTransportError:
                    # for DES-3028, mdix_state set request has timeout error, but it's ok if the value was set correctly
                    mdix_state = (await self._get_port_data(["mdix_state"]))["mdix_state"]
                    if request["mdix_state"] != mdix_state:
                        raise
            
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### CABLE DIAGNOSTICS ### 

    async def get_cable_diagnostics_for_port(self) -> ResponseData:
        if self._is_combo_port and self._is_combo_fiber_port is None:
            await self._check_fiber_combo_port()
        
        if self._is_combo_fiber_port or self._is_fiber_port:
            return {"unable_to_perform": True}

        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], ["cable_diagnostics_action"])
        payload["cable_diagnostics_action"]["set_value"] = "action"

        action_status = await self._set(payload)
        while action_status["cable_diagnostics_action"] in {"action", "processing"}:
            action_status = await self._get(payload)
        
        include_oids = []
        pairs = 4 if self._is_gigabit_ethernet_port else 2

        for i in range(1, pairs + 1):
            include_oids.append(f"cable_diagnostics_pair{i}_status")
            include_oids.append(f"cable_diagnostics_pair{i}_length")
        
        pairs_tests = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids))
        results = {f"pair{i}": {} for i in range(1, pairs + 1)}

        results["unable_to_perform"] = False
        results["no_cable"] = True
        need_to_order_pairs = self._is_gigabit_ethernet_port and not self._config["models"][self._model]["are_cable_diagnostics_pairs_ordered"]

        def get_actual_pair_number(pair_number: int) -> int:
            if not need_to_order_pairs or pair_number == 4:
                return pair_number
            if pair_number == 1:
                return 3
            if pair_number == 2:
                return 1
            return 2

        for i in range(1, pairs + 1):
            results[f"pair{get_actual_pair_number(i)}"] = {"status": pairs_tests[f"cable_diagnostics_pair{i}_status"],
                                                           "length": pairs_tests[f"cable_diagnostics_pair{i}_length"]}
            if pairs_tests[f"cable_diagnostics_pair{i}_status"] != "no_cable":
                results["no_cable"] = False

        return results

    ### PORT SECURITY ###

    async def get_port_security_on_port(self) -> ResponseData:
        include_oids = ["port_security_max_learning_addresses", "port_security_lock_address_mode", "port_security_admin_state"]
        results = await self._get_port_data(include_oids)
        return {key.removeprefix("port_security_"): value for key, value in results.items()}
    
    async def set_port_security_on_port(self, request: RequestData) -> SNMPResponseCode:
        include_oids = [f"port_security_{param}" for param in request.keys()]
        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids)

        for param, data in payload.items():
            data["set_value"] = request[param.removeprefix("port_security_")]
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # clear static fdb on port by switching port security mode on port
    async def clear_port_security_on_port(self) -> SNMPResponseCode:
        current_mode = (await self._get_port_data(["port_security_lock_address_mode"]))["port_security_lock_address_mode"]
        temp_mode = "permanent" if current_mode == "delete_on_reset" else "delete_on_reset"

        result = await self.set_port_security_on_port({"lock_address_mode": temp_mode})
        if result != SNMPResponseCode.SUCCESS:
            return result
        return await self.set_port_security_on_port({"lock_address_mode": current_mode})
    
    async def clear_port_security_exact_mac_addresses(self, request: RequestData) -> SNMPResponseCode:
        vlan_table = await self.get_vlan_static_table()

        clear_port_security_config = SNMPClient._filter_request_config(self._switch_oids_config["port"],
                                                    ["clear_port_security_vlan_name", "clear_port_security_port",
                                                     "clear_port_security_mac_address", "clear_port_security_action"])
        all_payload_data = {
            f"clear_port_security.{vlan_table[mac_data["vlan_id"]]["vlan_name"]}.{mac_data["mac_address"]}": {
                "clear_port_security_vlan_name": {**clear_port_security_config["clear_port_security_vlan_name"], "set_value": vlan_table[mac_data["vlan_id"]]["vlan_name"]},
                "clear_port_security_port": {**clear_port_security_config["clear_port_security_port"], "set_value": mac_data["port"]},
                "clear_port_security_mac_address": {**clear_port_security_config["clear_port_security_mac_address"], "set_value": mac_data["mac_address"]},
                "clear_port_security_action": {**clear_port_security_config["clear_port_security_action"], "set_value": "start"}
            }
            for mac_data in request["mac_addresses_list"]
        }

        try:
            for request, payload in all_payload_data.items():
                result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### LOOPBACK DETECTION ###

    async def get_loopdetect_on_port(self) -> ResponseData:
        include_oids = ["loopdetect_state", "loopdetect_status"]
        result = await self._get_port_data(include_oids)
        return {key.removeprefix("loopdetect_"): value for key, value in result.items()}
    
    async def set_loopdetect_on_port(self, request: RequestData) -> SNMPResponseCode:
        include_oids = [f"loopdetect_{param}" for param in request.keys()]
        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids)

        for param, data in payload.items():
            data["set_value"] = request[param.removeprefix("loopdetect_")]

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### PORT UTILIZATION ###

    async def get_port_utilization(self) -> ResponseData:
        include_oids = ["utilization_tx_frames", "utilization_rx_frames", "utilization_percentage"]
        return await self._get_port_data(include_oids)
    
    ### BANDWIDTH CONTROL ###

    async def get_bandwidth_control_on_port(self) -> ResponseData:
        include_oids = ["bandwidth_control_rx_rate", "bandwidth_control_tx_rate"]
        results = await self._get_port_data(include_oids)
        return {key.removeprefix("bandwidth_control_"): value for key, value in results.items()}
    
    async def set_bandwidth_control_on_port(self, request: RequestData) -> SNMPResponseCode:
        include_oids = [f"bandwidth_control_{param}" for param in request.keys()]
        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids)

        for param, data in payload.items():
            data["set_value"] = request[param.removeprefix("bandwidth_control_")]
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### TRAFFIC CONTROL ###
    
    async def get_traffic_control_on_port(self) -> ResponseData:
        include_oids = ["traffic_control_threshold", "traffic_control_broadcast_status", "traffic_control_multicast_status", "traffic_control_unicast_status",
                        "traffic_control_action_status", "traffic_control_count_down", "traffic_control_time_interval"]
        results = await self._get_port_data(include_oids)
        return {key.removeprefix("traffic_control_"): value for key, value in results.items()}
    
    async def set_traffic_control_on_port(self, request: RequestData) -> SNMPResponseCode:
        include_oids = [f"traffic_control_{param}" for param in request.keys()]
        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids)

        for param, data in payload.items():
            data["set_value"] = request[param.removeprefix("traffic_control_")]
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### TRAFFIC SEGMENTATION ###

    async def get_traffic_segmentation_for_port(self) -> ResponseData:
        result = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["port"], ["traffic_segmentation_forward_ports"]))
        portlist = L2SwitchClient._parse_assigned_ports_from_hex(result["traffic_segmentation_forward_ports"], self._ports_count)
        return {"forward_ports": portlist}

    async def set_traffic_segmentation_for_port(self, request: RequestData) -> SNMPResponseCode:
        include_oids = [f"traffic_segmentation_{param}" for param in request.keys()]
        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids)

        for param, data in payload.items():
            data["set_value"] = L2SwitchClient._combine_assigned_ports_to_hex(request[param.removeprefix("traffic_segmentation_")])

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### PORT STATISCTICS ###

    async def _get_packets_speed(self, packet_type: str) -> ResponseData:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], [packet_type])

        start_packets = (await self._get(payload))[packet_type]
        start_time = perf_counter()
        await asyncio.sleep(0.5)
        
        end_packets = (await self._get(payload))[packet_type]
        end_time = perf_counter()
        speed = int((end_packets - start_packets) / (end_time - start_time))
        return {packet_type: speed}
    
    async def get_rx_tx_megabit_speed_on_port(self) -> ResponseData:
        task_rx_bytes = asyncio.create_task(self._get_packets_speed("rx_bytes"))
        task_tx_bytes = asyncio.create_task(self._get_packets_speed("tx_bytes"))
        
        results = await asyncio.gather(task_rx_bytes, task_tx_bytes)
        return {f"{key.removesuffix('bytes')}megabit": L2SwitchClient._byte_to_megabit(value) for res in results for key, value in res.items()}
    
    async def get_rx_tx_packets_all_types_on_port(self) -> ResponseData:
        include_oids = ["rx_unicast_packets", "rx_multicast_packets", "rx_broadcast_packets",
                        "tx_unicast_packets", "tx_multicast_packets", "tx_broadcast_packets"]
        tasks = [asyncio.create_task(self._get_packets_speed(key)) for key in include_oids]

        results = await asyncio.gather(*tasks)
        return {key: value for res in results for key, value in res.items()}
    
    async def get_all_packet_statistics_on_port(self) -> ResponseData:
        task_megabit = asyncio.create_task(self.get_rx_tx_megabit_speed_on_port())
        task_packets = asyncio.create_task(self.get_rx_tx_packets_all_types_on_port())

        results = await asyncio.gather(task_megabit, task_packets)
        return results[0] | results[1]
    
    async def get_crc_errors_on_port(self) -> ResponseData:
        include_oids = ["alignment_errors", "fcs_errors"]
        return await self._get_port_data(include_oids)

    async def clear_all_counters(self) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["switch"], ["clear_all_counters"])
        payload["clear_all_counters"]["set_value"] = "active"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### HELPER FUNCTIONS ###

    @override
    def _render_get_set_oid(self, oid: str, **params) -> str:
        return oid.format(port=self._port, **params)

    @staticmethod
    def _parse_last_index(oid: str) -> tuple[str, int]:
        parts = oid.rpartition(".")
        return parts[0], int(parts[2])

    @staticmethod
    def _build_octet_by_pattern(data_tuple: tuple[int], pattern: str) -> bytes:
        mapping = {"1": "B", "2": "H", "4": "I", "8": "Q"}
        fmt = ">" + "".join(mapping[bytes_count] for bytes_count in pattern)
        res= struct.pack(fmt, *data_tuple)
        print(res)
        print(type(res))
        return struct.pack(fmt, *data_tuple)

    @staticmethod
    def _parse_assigned_ports_from_hex(octet_string: str, ports_count: int) -> set[int]:
        num_val = int(octet_string, 16)
        return {i + 1 for i in range(ports_count) if (num_val >> (63 - i)) & 1}

    @staticmethod
    def _combine_assigned_ports_to_hex(portlist: set[int]) -> bytearray:
        result = bytearray(8)

        for port in portlist:
            byte_index = (port - 1) // 8
            bit_index = (port - 1) % 8
            result[byte_index] |= 1 << (7 - bit_index)
        
        return result

    @staticmethod
    def _parse_acl_packet_content_fully_inspected_bytes(mask: str) -> set[int]:
        return {ind for ind, byte in enumerate(bytes.fromhex(mask)) if byte == 0xFF}

    @staticmethod
    def _discover_acl_packet_content_ipv4_arp_check_state(fully_inspected_bytes: set[int]) -> str:
        ipv4_check_state = all(byte in fully_inspected_bytes for byte in SNMP.SOURCE_IP_BYTES_IN_IPV4)
        arp_check_state = all(byte in fully_inspected_bytes for byte in SNMP.SOURCE_IP_BYTES_IN_ARP)
        if ipv4_check_state:
            ipv4_arp_check_state = "both" if arp_check_state else "ipv4"
        else:
            ipv4_arp_check_state = "arp" if arp_check_state else "none"
        
        return ipv4_arp_check_state

    @staticmethod
    def _parse_acl_chunk_to_ip(acl_entry: str) -> str:
        return ".".join([str(int(acl_entry[2:][2*i : 2*i+2], 16)) for i in range(4)])

    @staticmethod
    def _parse_ip_address_from_oid(oid: str) -> tuple[str, str]:
        oid, *ip_address = oid.rsplit(".", 4)
        ip_address = ".".join(ip_address[-4:])
        return oid, ip_address
    
    @staticmethod
    def _convert_name_into_oid(name: str) -> str:
        return f"{len(name)}.{'.'.join(str(ord(sym)) for sym in name)}"

    @staticmethod
    def _get_request_name_for_vlan_status(status: str) -> str | None:
        match status:
            case "untagged":
                return "untagged_ports"
            case "tagged":
                return "egress_ports"
            case _:
                return None
    
    @staticmethod
    def _parse_vlan_id_mac_from_oid_suffix(oid: str) -> tuple[str, str]:
        oid, vlan_id, *mac = oid.rsplit(".", 7)
        vlan_id = int(vlan_id)
        mac = "-".join([f"{int(octet):02X}" for octet in mac])
        return oid, vlan_id, mac
    
    @staticmethod
    def _byte_to_megabit(bytes_count: int) -> int:
        return round(bytes_count * 8 / 1024 / 1024)