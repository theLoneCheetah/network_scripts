#!/usr/bin/python3
import asyncio
from typing import override, Any
from collections import defaultdict
from pysnmp.hlapi.v3arch.asyncio import *
from snmp_client import SNMPClient
from const import SNMP

class L2SwitchClient(SNMPClient):
    _ports_count: int
    _model: str
    _port: int
    _is_gigabit_ethernet_port: bool
    _is_combo_port: bool
    _check_combo_fiber_port_lock: asyncio.Lock
    _is_combo_fiber_port: bool | None
    _is_fiber_port: bool
    _switch_oids_config: dict[str, Any]
    
    def __init__(self, ipaddress: str, port: int, model: str) -> None:
        super().__init__(ipaddress)

        self._ports_count = self._config["models"][model]["ports_count"]
        self._model = self._config["models"][model]["base_model"]
        self._port = port

        self._is_gigabit_ethernet_port = self._port >= self._config["models"][self._model]["first_gigabit_port"]
        self._is_combo_port = self._port in self._config["models"][self._model]["combo_ports"]
        self._check_combo_fiber_port_lock = asyncio.Lock()
        self._is_combo_fiber_port = None
        self._is_fiber_port = self._port in self._config["models"][self._model]["fiber_ports"]

        self._switch_oids_config = self._config["models"][self._model]["oids"]
    
    async def get_switch_info(self, include_oids: list[str]) -> dict[str, Any]:
        return await self._get(SNMPClient._filter_request_config(self._switch_oids_config["switch"], include_oids))
    
    async def get_dhcp_relay(self):
        pass
    
    async def get_vlan_static_table(self) -> defaultdict[int, dict[str, Any]]:
        def parse_vlan_id(oid: str) -> int:
            return int(oid.rpartition(".")[2])
        
        def parse_assignes_ports(octet_string: str) -> set[str]:
            num_val = int(octet_string, 16)
            return {i + 1 for i in range(self._ports_count) if (num_val >> (63 - i)) & 1}
        
        results = defaultdict(dict)
        
        for oid, vlan_name in await self._bulk_walk(self._switch_oids_config["vlan"]["name"]):
            results[parse_vlan_id(oid)]["vlan_name"] = vlan_name
        
        for oid, octet_string in await self._bulk_walk(self._switch_oids_config["vlan"]["egress_ports"]):
            results[parse_vlan_id(oid)]["tagged_ports"] = parse_assignes_ports(octet_string)
        
        for oid, octet_string in await self._bulk_walk(self._switch_oids_config["vlan"]["untagged_ports"]):
            vlan_id = parse_vlan_id(oid)
            results[vlan_id]["untagged_ports"] = parse_assignes_ports(octet_string)
            results[vlan_id]["tagged_ports"] -= results[vlan_id]["untagged_ports"]

        return results
    
    async def get_fdb_table(self) -> defaultdict[int, dict[str, dict[str, Any]]]:
        def parse_vlan_id_mac(oid: str, base_oid: str) -> tuple[str, str]:
            vlan_id_mac = oid.partition(base_oid + ".")[2]
            vlan_id, mac = vlan_id_mac.split(".", 1)
            vlan_id = int(vlan_id)
            mac = "-".join([f"{int(octet):02X}" for octet in mac.split(".")])
            return vlan_id, mac
        
        results = defaultdict(dict)

        mac_port = await self._bulk_walk(self._switch_oids_config["fdb"]["port"])

        for oid, port in mac_port:
            vlan_id, mac = parse_vlan_id_mac(oid, self._switch_oids_config["fdb"]["port"]["oid"])
            # default status is dynamic, so if mac's status won't be found it means it's dynamic
            results[vlan_id][mac] = {"port": port, "status": "dynamic"}
        
        status_port = await self._bulk_walk(self._switch_oids_config["fdb"]["status"])

        for oid, status in status_port:
            vlan_id, mac = parse_vlan_id_mac(oid, self._switch_oids_config["fdb"]["status"]["oid"])
            if status not in {"invalid" , "self"}:
                status = "dynamic" if status == "learned" else "static"
            if mac in results[vlan_id]:   # if mac's port is unknown, don't count it
                results[vlan_id][mac]["status"] = status

        return results
    
    async def get_cable_diagnostics_port(self) -> dict[str, Any]:
        if self._is_combo_port and self._is_combo_fiber_port is None:
            await self._check_fiber_combo_port()
        
        if self._is_combo_fiber_port or self._is_fiber_port:
            print("hey")
            return {"unable_to_perform": True}

        filtered_request_config = SNMPClient._filter_request_config(self._switch_oids_config["port"], ["cable_diagnostics_action"])

        action_status = await self._set(filtered_request_config, {"cable_diagnostics_action": "action"})
        while action_status["cable_diagnostics_action"] in {"action", "processing"}:
            action_status = await self._get(filtered_request_config)
        
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

    @override
    def _render_oid(self, oid: str) -> str:
        return oid.format(port=self._port)
    