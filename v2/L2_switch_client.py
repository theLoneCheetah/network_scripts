#!/usr/bin/python3
import asyncio
from typing import override, Any
from collections import defaultdict
from datetime import datetime
from pysnmp.hlapi.v3arch.asyncio import *
from snmp_client import SNMPClient
from const import SNMP
from snmp_exceptions import *

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

    async def scan_available_mibs(self) -> dict[str, dict[str, Any]]:
        def parse_index(oid: str) -> int:
            return int(oid.rpartition(".")[2])
        
        results = defaultdict(dict)
        
        for oid, desciption in await self._bulk_walk(self._switch_oids_config["private_mib_modules"]["description"]):
            results[parse_index(oid)]["desciption"] = desciption

        for oid, version in await self._bulk_walk(self._switch_oids_config["private_mib_modules"]["version"]):
            results[parse_index(oid)]["version"] = version

        for oid, value_type in await self._bulk_walk(self._switch_oids_config["private_mib_modules"]["value_type"]):
            results[parse_index(oid)]["value_type"] = value_type
        
        return {value["desciption"]: {"version": value["version"], "value_type": value["value_type"]} for value in results.values()}

    ### SWITCH INFO ###

    async def get_switch_info(self, include_oids: list[str]) -> dict[str, Any]:
        return await self._get(SNMPClient._filter_request_config(self._switch_oids_config["switch"], include_oids))
    
    async def get_current_time(self) -> dict[str, datetime]:
        result = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["switch"], ["current_time"]))
        command_name, current_time_tuple = next(iter(result.items()))
        return {command_name: datetime(*current_time_tuple)}
    
    #### DHCP RELAY ###

    async def get_dhcp_relay(self) -> dict[str, Any]:
        def parse_ip_address(oid: str) -> str:
            return ".".join(oid.rsplit(".", 4)[-4:])

        include_oids = ["state", "option82_state", "option82_check_state", "option82_policy", "option82_remote_id_type"]
        results = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["dhcp_relay"], include_oids))

        results["interfaces_ip_addresses_vlan_ids"] = defaultdict(dict)

        for oid, interface_name in await self._bulk_walk(self._switch_oids_config["dhcp_relay"]["interface_name_for_server"]):
            results["interfaces_ip_addresses_vlan_ids"][interface_name][parse_ip_address(oid)] = set()
        
        return results
    
    ### VLAN ###

    async def get_vlan_static_table(self) -> defaultdict[int, dict[str, Any]]:
        def parse_vlan_id(oid: str) -> int:
            return int(oid.rpartition(".")[2])
        
        def parse_assigned_ports(octet_string: str) -> set[str]:
            num_val = int(octet_string, 16)
            return {i + 1 for i in range(self._ports_count) if (num_val >> (63 - i)) & 1}
        
        results = defaultdict(dict)
        
        for oid, vlan_name in await self._bulk_walk(self._switch_oids_config["vlan"]["all_names"]):
            # consider default empty sets for tagged/untagged ports
            results[parse_vlan_id(oid)] = {"vlan_name": vlan_name, "tagged_ports": set(), "untagged_ports": set()}
        
        # tagged vlans
        vlan_config = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["egress_ports"])["egress_ports"]
        payload = {}

        for vlan_id in results:
            config_copy = vlan_config.copy()
            config_copy["params"] = {"vlan_id": vlan_id}
            payload[f"egress_ports.{vlan_id}"] = config_copy
        
        for request_name, octet_string in (await self._get(payload)).items():
            results[parse_vlan_id(request_name)]["tagged_ports"] = parse_assigned_ports(octet_string)
        
        # untagged vlan
        vlan_config = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["untagged_ports"])["untagged_ports"]
        payload = {}

        for vlan_id in results:
            config_copy = vlan_config.copy()
            config_copy["params"] = {"vlan_id": vlan_id}
            payload[f"untagged_ports.{vlan_id}"] = config_copy
        
        for request_name, octet_string in (await self._get(payload)).items():
            vlan_id = parse_vlan_id(request_name)
            results[vlan_id]["untagged_ports"] = parse_assigned_ports(octet_string)
            results[vlan_id]["tagged_ports"] -= results[vlan_id]["untagged_ports"]

        return results
    
    async def check_vlan_entry(self, vlan: dict[str, Any]) -> dict[str, Any]:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["entry_status"])
        payload["entry_status"]["params"] = {"vlan_id": vlan["vlan_id"]}
        return await self._get(payload)
    
    async def create_vlan(self, vlan: dict[str, Any]) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["name", "entry_status"])
        for command in payload.values():
            command["params"] = {"vlan_id": vlan["vlan_id"]}
        
        payload["name"]["set_value"] = vlan["vlan_name"]
        payload["entry_status"]["set_value"] = "create_go"

        try:
            result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "commitFailed":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR

    async def delete_vlan(self, vlan: dict[str, Any]) -> SNMPResponseCode:
        print(await self.get_ports_with_vlan_status(vlan, "untagged"))
        check_result = await self.check_vlan_entry(vlan)
        if check_result["entry_status"] is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["entry_status"])
        payload["entry_status"]["params"] = {"vlan_id": vlan["vlan_id"]}
        payload["entry_status"]["set_value"] = "destroy"
        
        try:
            result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
    
    async def get_ports_with_vlan_status(self, vlan: dict[str, Any], status: str):
        request_name = L2SwitchClient._get_request_name_for_vlan_status(status)
        if request_name is None:
            return SNMPResponseCode.INVALID_DATA

        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], [request_name])
        payload[request_name]["params"] = {"vlan_id": vlan["vlan_id"]}

        result = await self._get(payload)
        return result
    
    async def add_vlan_on_ports(self, portlist: list[int], vlan: dict[str, Any], status: str) -> SNMPResponseCode:
        request_name = L2SwitchClient._get_request_name_for_vlan_status(status)
        if request_name is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], [request_name])
        payload[request_name]["params"] = {"vlan_id": vlan["vlan_id"]}
        payload[request_name]["set_value"] = L2SwitchClient._combine_assigned_ports_to_hex(portlist)
        
        try:
            result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR

    ### MAC ADDRESS ##

    async def get_fdb_table(self) -> defaultdict[int, dict[str, dict[str, Any]]]:
        def parse_vlan_id_mac(oid: str, base_oid: str) -> tuple[str, str]:
            vlan_id_mac = oid.partition(base_oid + ".")[2]
            vlan_id, mac = vlan_id_mac.split(".", 1)
            vlan_id = int(vlan_id)
            mac = "-".join([f"{int(octet):02X}" for octet in mac.split(".")])
            return vlan_id, mac
        
        results = defaultdict(dict)

        for oid, port in await self._bulk_walk(self._switch_oids_config["fdb"]["port"]):
            vlan_id, mac = parse_vlan_id_mac(oid, self._switch_oids_config["fdb"]["port"]["oid"])
            # default status is dynamic, so if mac's status won't be found it means it's dynamic
            results[vlan_id][mac] = {"port": port, "status": "dynamic"}

        for oid, status in await self._bulk_walk(self._switch_oids_config["fdb"]["status"]):
            vlan_id, mac = parse_vlan_id_mac(oid, self._switch_oids_config["fdb"]["status"]["oid"])
            if status not in {"invalid" , "self"}:
                status = "dynamic" if status == "learned" else "static"
            if mac in results[vlan_id]:   # if mac's port is unknown, don't count it
                results[vlan_id][mac]["status"] = status

        return results
    
    ### CABLE DIAGNOSTICS ### 

    async def get_cable_diagnostics_port(self) -> dict[str, Any]:
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
        need_to_order_pairs = self._is_gigabit_ethernet_port and not self._config["models"][self._model]["is_cable_diagnostics_pairs_ordered"]

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
    
    ### PORT INFO ###

    async def _check_fiber_combo_port(self) -> None:
        async with self._check_combo_fiber_port_lock:
            if self._is_combo_fiber_port is None:
                include_oids = ["link_status", "link_status_combo_fiber"]
                copper_fiber_statuses = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids))

                if copper_fiber_statuses["link_status"] != "link_pass" and copper_fiber_statuses["link_status_combo_fiber"] == "link_pass":
                    self._is_combo_fiber_port = True
                else:
                    self._is_combo_fiber_port = False

    async def get_port_diagnostics(self, include_oids: list[str]) -> dict[str, Any]:
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

    ### HELPER FUNCTIONS ###

    @override
    def _render_oid(self, oid: str, **params) -> str:
        return oid.format(port=self._port, **params)
    
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
    def _combine_assigned_ports_to_hex(portlist: list[int]) -> str:
        result = bytearray(8)

        for port in portlist:
            byte_index = (port - 1) // 8
            bit_index = (port - 1) % 8
            result[byte_index] |= 1 << (7 - bit_index)
        
        return result