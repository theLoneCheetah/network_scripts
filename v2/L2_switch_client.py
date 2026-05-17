#!/usr/bin/python3
import asyncio
import struct
from typing import override, Any
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from pysnmp.hlapi.v3arch.asyncio import *
from snmp_client import SNMPClient
from const import SNMP
from snmp_exceptions import *

type RequestData = dict[str, Any]
type ResponseData = dict[str, Any]

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
                await self._change_ip_address(request["ip"])
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
    
    ### DHCP RELAY ###

    async def get_dhcp_relay(self) -> ResponseData:
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
    async def _check_vlan_entry(self, vlan_id: int) -> ResponseData:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["entry_status"])
        payload["entry_status"]["params"] = {"vlan_id": vlan_id}
        return await self._get(payload)
    
    async def create_vlan(self, request: RequestData) -> SNMPResponseCode:
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], ["name", "entry_status"])
        for command in payload.values():
            command["params"] = {"vlan_id": request["vlan"]["vlan_id"]}
        
        payload["name"]["set_value"] = request["vlan"]["vlan_name"]
        payload["entry_status"]["set_value"] = "create_go"

        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "commitFailed":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    async def delete_vlan(self, request: RequestData) -> SNMPResponseCode:
        check_result = await self._check_vlan_entry(request["vlan_id"])
        if check_result["entry_status"] is None:
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
        check_result = await self._check_vlan_entry(request["vlan_id"])
        if check_result["entry_status"] is None:
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
        check_result = await self._check_vlan_entry(request["vlan_id"])
        if check_result["entry_status"] is None:
            return SNMPResponseCode.INVALID_DATA

        status = "tagged"
        result_portlist = await self._get_ports_with_vlan_status(request["vlan_id"], status) - request["portlist"]
        
        request_name = L2SwitchClient._get_request_name_for_vlan_status(status)
        if request_name is None:
            return SNMPResponseCode.INVALID_DATA
        
        payload = SNMPClient._filter_request_config(self._switch_oids_config["vlan"], [request_name])
        payload[request_name]["params"] = {"vlan_id": request["vlan_id"]}
        payload[request_name]["set_value"] = L2SwitchClient._combine_assigned_ports_to_hex(result_portlist)
        
        try:
            result = await self._set(payload)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

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
    
    async def get_mac_addresses_on_port(self) -> ResponseData:
        fdb_table = await self.get_fdb_table()
        result = defaultdict(dict)

        for vlan_id, mac_list in fdb_table.items():
            for mac, mac_info in mac_list.items():
                if mac_info["port"] == self._port and mac_info["status"] not in {"invalid" , "self"}:
                    result[mac][vlan_id] = {"status": mac_info["status"]}
        
        return result
    
    ### FLOOD FDB ###

    async def get_flood_fdb(self) -> ResponseData:
        results = await self._get(SNMPClient._filter_request_config(self._switch_oids_config["flood_fdb"], ["state"]))
        if results["state"] == "disabled":
            return results
        
        table = defaultdict(dict)
        
        for oid, status in await self._bulk_walk(self._switch_oids_config["flood_fdb"]["status"]):
            index, vlan_id_mac = L2SwitchClient._cut_base_oid_from_oid(oid, self._switch_oids_config["flood_fdb"]["status"]["oid"]).split(".", 1)
            index = int(index)
            vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(vlan_id_mac)
            table[index][mac] = {"vlan_id": vlan_id, "status": status}
        
        for oid, timestamp in await self._bulk_walk(self._switch_oids_config["flood_fdb"]["timestamp"]):
            index, vlan_id_mac = L2SwitchClient._cut_base_oid_from_oid(oid, self._switch_oids_config["flood_fdb"]["timestamp"]["oid"]).split(".", 1)
            index = int(index)
            vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(vlan_id_mac)
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

    async def get_cable_diagnostics_port(self) -> ResponseData:
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
        include_oids = [F"port_security_{param}" for param in request.keys()]
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
        include_oids = [F"loopdetect_{param}" for param in request.keys()]
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
        include_oids = [F"bandwidth_control_{param}" for param in request.keys()]
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
        include_oids = [F"traffic_control_{param}" for param in request.keys()]
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
        include_oids = [F"traffic_segmentation_{param}" for param in request.keys()]
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

    ### HELPER FUNCTIONS ###

    @override
    def _render_oid(self, oid: str, **params) -> str:
        return oid.format(port=self._port, **params)

    @staticmethod
    def _build_octet_by_pattern(data_tuple: tuple[int], pattern: str) -> bytes:
        mapping = {"1": "B", "2": "H", "4": "I", "8": "Q"}
        fmt = ">" + "".join(mapping[bytes_count] for bytes_count in pattern)
        return struct.pack(fmt, *data_tuple)

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
    def _cut_base_oid_from_oid(oid: str, base_oid: str) -> str:
        return oid.partition(base_oid + ".")[2]
    
    @staticmethod
    def _parse_vlan_id_mac_from_oid_suffix(oid_suffix: str) -> tuple[str, str]:
        vlan_id, *mac = oid_suffix.split(".")
        vlan_id = int(vlan_id)
        mac = "-".join([f"{int(octet):02X}" for octet in mac])
        return vlan_id, mac