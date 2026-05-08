#!/usr/bin/python3
import asyncio
from typing import override, Any
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from pysnmp.hlapi.v3arch.asyncio import *
from snmp_client import SNMPClient
from const import SNMP
from snmp_exceptions import *

type RequestData = dict[str, Any]

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
        results = defaultdict(dict)
        
        for oid, desciption in await self._bulk_walk(self._switch_oids_config["private_mib_modules"]["description"]):
            results[L2SwitchClient._parse_last_index(oid)[1]]["desciption"] = desciption

        for oid, version in await self._bulk_walk(self._switch_oids_config["private_mib_modules"]["version"]):
            results[L2SwitchClient._parse_last_index(oid)[1]]["version"] = version

        for oid, value_type in await self._bulk_walk(self._switch_oids_config["private_mib_modules"]["value_type"]):
            results[L2SwitchClient._parse_last_index(oid)[1]]["value_type"] = value_type
        
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
        include_oids = ["state", "option82_state", "option82_check_state", "option82_policy", "option82_remote_id_type"]
        results = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["dhcp_relay"], include_oids))

        results["interfaces_ip_addresses_vlan_ids"] = defaultdict(dict)

        for oid, interface_name in await self._bulk_walk(self._switch_oids_config["dhcp_relay"]["interface_name_for_server"]):
            results["interfaces_ip_addresses_vlan_ids"][interface_name][L2SwitchClient._parse_ip_address_from_oid(oid)[1]] = set()
        
        return results
    
    ### VLAN ###

    async def get_vlan_static_table(self) -> defaultdict[int, dict[str, Any]]:
        results = defaultdict(dict)
        
        for oid, vlan_name in await self._bulk_walk(self._switch_oids_config["vlan"]["all_names"]):
            vlan_id = L2SwitchClient._parse_last_index(oid)[1]
            # consider default empty sets for tagged/untagged ports
            results[vlan_id] = {"vlan_name": vlan_name, "tagged_ports": set(), "untagged_ports": set()}
        
        # tagged
        for oid, octet_string in await self._bulk_walk(self._switch_oids_config["vlan"]["all_egress_ports"]):
            vlan_id = L2SwitchClient._parse_last_index(oid)[1]
            portlist = L2SwitchClient._parse_assigned_ports_from_hex(octet_string, self._ports_count)
            # for first discovered vlan, consider vlan name is the same as vlan id
            if vlan_id not in results:
                results[vlan_id] = {"vlan_name": str(vlan_id), "untagged_ports": set()}
            results[vlan_id]["tagged_ports"] = portlist
        
        # untagged
        for oid, octet_string in await self._bulk_walk(self._switch_oids_config["vlan"]["all_untagged_ports"]):
            vlan_id = L2SwitchClient._parse_last_index(oid)[1]
            portlist = L2SwitchClient._parse_assigned_ports_from_hex(octet_string, self._ports_count)
            # for first discovered vlan, consider vlan name is the same as vlan id
            if vlan_id not in results:
                results[vlan_id] = {"vlan_name": str(vlan_id), "tagged_ports": set(), "untagged_ports": portlist}
            results[vlan_id]["untagged_ports"] = portlist
            results[vlan_id]["tagged_ports"] -= results[vlan_id]["untagged_ports"]

        return results
    
    async def get_vlan_on_port(self) -> defaultdict[str, set[int]]:
        vlan_static_table = await self.get_vlan_static_table()
        result = defaultdict(dict)

        for vlan_id, vlan_info in vlan_static_table.items():
            vlan_name =  vlan_info["vlan_name"]
            if self._port in vlan_info["tagged_ports"]:
                result["tagged"][vlan_id] = vlan_name
            elif self._port in vlan_info["untagged_ports"]:
                result["untagged"][vlan_id] = vlan_name

        return result
    
    async def _check_vlan_entry(self, vlan: dict[str, Any]) -> dict[str, Any]:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["entry_status"])
        payload["entry_status"]["params"] = {"vlan_id": vlan["vlan_id"]}
        return await self._get(payload)
    
    async def create_vlan(self, request: RequestData) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["name", "entry_status"])
        for command in payload.values():
            command["params"] = {"vlan_id": request["vlan"]["vlan_id"]}
        
        payload["name"]["set_value"] = request["vlan"]["vlan_name"]
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

    async def delete_vlan(self, request: RequestData) -> SNMPResponseCode:
        check_result = await self._check_vlan_entry(request["vlan"])
        if check_result["entry_status"] is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["entry_status"])
        payload["entry_status"]["params"] = {"vlan_id": request["vlan"]["vlan_id"]}
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
    
    async def _get_ports_with_vlan_status(self, vlan: dict[str, Any], status: str) -> set[int]:
        request_name = L2SwitchClient._get_request_name_for_vlan_status(status)
        if request_name is None:
            return SNMPResponseCode.INVALID_DATA

        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], [request_name])
        payload[request_name]["params"] = {"vlan_id": vlan["vlan_id"]}

        result = await self._get(payload)
        ports = L2SwitchClient._parse_assigned_ports_from_hex(result[request_name], self._ports_count)
        return ports
    
    async def add_vlan_on_ports(self, request: RequestData) -> SNMPResponseCode:
        request_name = L2SwitchClient._get_request_name_for_vlan_status(request["status"])
        if request_name is None:
            return SNMPResponseCode.INVALID_DATA
        
        # for ports that were untagged, untagged + egress -> untagged
        portlist = request["portlist"] | await self._get_ports_with_vlan_status(request["vlan"], request["status"])
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], [request_name])
        payload[request_name]["params"] = {"vlan_id": request["vlan"]["vlan_id"]}
        payload[request_name]["set_value"] = L2SwitchClient._combine_assigned_ports_to_hex(portlist)
        
        try:
            result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "commitFailed":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
    
    async def delete_vlan_from_ports(self, request: RequestData) -> SNMPResponseCode:
        status = "tagged"
        result_portlist = await self._get_ports_with_vlan_status(request["vlan"], status) - request["portlist"]
        
        request_name = L2SwitchClient._get_request_name_for_vlan_status(status)
        if request_name is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], [request_name])
        payload[request_name]["params"] = {"vlan_id": request["vlan"]["vlan_id"]}
        payload[request_name]["set_value"] = L2SwitchClient._combine_assigned_ports_to_hex(result_portlist)
        
        try:
            result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR

    ### MAC ADDRESS ###

    async def get_fdb_table(self) -> defaultdict[int, dict[str, dict[str, Any]]]:
        results = defaultdict(dict)

        for oid, port in await self._bulk_walk(self._switch_oids_config["fdb"]["port"]):
            vlan_id_mac = L2SwitchClient._cut_base_oid_from_oid(oid, self._switch_oids_config["fdb"]["port"]["oid"])
            vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(vlan_id_mac)
            # default status is dynamic, so if mac's status won't be found it means it's dynamic
            results[vlan_id][mac] = {"port": port, "status": "dynamic"}

        for oid, status in await self._bulk_walk(self._switch_oids_config["fdb"]["status"]):
            vlan_id_mac = L2SwitchClient._cut_base_oid_from_oid(oid, self._switch_oids_config["fdb"]["status"]["oid"])
            vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(vlan_id_mac)
            if status not in {"invalid" , "self"}:
                status = "dynamic" if status == "learned" else "static"
            if mac in results[vlan_id]:   # if mac's port is unknown, don't count it
                results[vlan_id][mac]["status"] = status

        return results
    
    async def get_mac_addresses_on_port(self) -> defaultdict[str, dict[int, dict[str, str]]]:
        fdb_table = await self.get_fdb_table()
        result = defaultdict(dict)

        for vlan_id, mac_list in fdb_table.items():
            for mac, mac_info in mac_list.items():
                if mac_info["port"] == self._port and mac_info["status"] not in {"invalid" , "self"}:
                    result[mac][vlan_id] = {"status": mac_info["status"]}
        
        return result
    
    
    ### FLOOD FDB ###

    async def get_flood_fdb_state(self) -> dict[str, str]:
        return await self._get(SNMPClient._filter_request_config(self._switch_oids_config["flood_fdb"], ["state"]))
    
    async def set_flood_fdb_state(self, request: RequestData) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["flood_fdb"], ["state"])
        payload["state"]["set_value"] = request["state"]

        try:
            result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR

    async def get_flood_fdb_table(self) -> dict[int, dict[str, dict[str, int]]]:
        results = defaultdict(dict)
        
        for oid, status in await self._bulk_walk(self._switch_oids_config["flood_fdb"]["status"]):
            index, vlan_id_mac = L2SwitchClient._cut_base_oid_from_oid(oid, self._switch_oids_config["flood_fdb"]["status"]["oid"]).split(".", 1)
            index = int(index)
            vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(vlan_id_mac)
            results[index][mac] = {"vlan_id": vlan_id, "status": status}
        
        for oid, timestamp in await self._bulk_walk(self._switch_oids_config["flood_fdb"]["timestamp"]):
            index, vlan_id_mac = L2SwitchClient._cut_base_oid_from_oid(oid, self._switch_oids_config["flood_fdb"]["timestamp"]["oid"]).split(".", 1)
            index = int(index)
            vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(vlan_id_mac)
            if index in results and mac in results[index]:   # if index or mac is unknown, don't count them
                results[index][mac]["timestamp"] = timestamp
        
        return results
    
    async def clear_flood_fdb_table(self) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["flood_fdb"], ["clear"])
        payload["clear"]["set_value"] = "start"

        try:
            result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
    
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

    ### PORT SECURITY ###

    async def get_port_security_on_port(self) -> dict[str, Any]:
        include_oids = ["port_security_max_learning_addresses", "port_security_lock_address_mode", "port_security_admin_state"]
        results = await self.get_port_diagnostics(include_oids)
        return {key.removeprefix("port_security_"): value for key, value in results.items()}
    
    async def set_port_security_on_port(self, request: RequestData) -> SNMPResponseCode:
        include_oids = [F"port_security_{param}" for param in request.keys()]
        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids)

        for param, data in payload.items():
            data["set_value"] = request[param.removeprefix("port_security_")]
        
        try:
            result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
    
    async def clear_port_security_on_port(self) -> SNMPResponseCode:
        vlan_table = await self.get_vlan_static_table()
        port_fdb_table = await self.get_mac_addresses_on_port()

        clear_port_security_config = SNMPClient._filter_request_config(self._switch_oids_config["port"],
                                                    ["clear_port_security_vlan_name", "clear_port_security_port",
                                                     "clear_port_security_mac_address", "clear_port_security_action"])
        all_payload_data = {
            f"clear_port_security.{vlan_table[vlan_id]["vlan_name"]}.{mac}": {
                "clear_port_security_vlan_name": {**clear_port_security_config["clear_port_security_vlan_name"], "set_value": vlan_table[vlan_id]["vlan_name"]},
                "clear_port_security_port": {**clear_port_security_config["clear_port_security_port"], "set_value": self._port},
                "clear_port_security_mac_address": {**clear_port_security_config["clear_port_security_mac_address"], "set_value": mac},
                "clear_port_security_action": {**clear_port_security_config["clear_port_security_action"], "set_value": "start"}
            }
            for mac, mac_data in port_fdb_table.items()
            for vlan_id in mac_data.keys()
        }

        try:
            for request, payload in all_payload_data.items():
                result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR

    ### LOOPBACK DETECTION ###

    async def get_loopdetect_on_port(self) -> dict[str, str]:
        include_oids = ["loopdetect_state", "loopdetect_status"]
        result = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["port"], include_oids))
        return {key.removeprefix("loopdetect_"): value for key, value in result.items()}
    
    async def set_loopdetect_state_on_port(self, request: RequestData) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["port"], ["loopdetect_state"])
        payload["loopdetect_state"]["set_value"] = request["state"]

        try:
            result = await self._set(payload)
            return SNMPResponseCode.SUCCESS
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR

    ### HELPER FUNCTIONS ###

    @override
    def _render_oid(self, oid: str, **params) -> str:
        return oid.format(port=self._port, **params)

    @staticmethod
    def _parse_last_index(oid: str) -> tuple[str, int]:
        parts = oid.rpartition(".")
        return parts[0], int(parts[2])

    @staticmethod
    def _parse_ip_address_from_oid(oid: str) -> tuple[str, str]:
        oid, *ip_address = oid.rsplit(".", 4)
        ip_address = ".".join(ip_address[-4:])
        return oid, ip_address

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
    def _parse_assigned_ports_from_hex(octet_string: str, ports_count: int) -> set[str]:
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
    def _cut_base_oid_from_oid(oid: str, base_oid: str) -> str:
        return oid.partition(base_oid + ".")[2]
    
    @staticmethod
    def _parse_vlan_id_mac_from_oid_suffix(oid_suffix: str) -> tuple[str, str]:
        vlan_id, *mac = oid_suffix.split(".")
        vlan_id = int(vlan_id)
        mac = "-".join([f"{int(octet):02X}" for octet in mac])
        return vlan_id, mac