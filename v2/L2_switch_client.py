#!/usr/bin/python3
import asyncio
from typing import override, Any
from collections import defaultdict
from pysnmp.hlapi.v3arch.asyncio import *
from snmp_client import SNMPClient
from const import SNMP

class L2SwitchClient(SNMPClient):
    _port: int
    _model: str
    _ports_count: int
    _switch_config: dict[str, Any]
    
    def __init__(self, ipaddress: str, port: int, model: str, ports_count: int) -> None:
        super().__init__(ipaddress)
        self._port = port
        self._model = model
        self._ports_count = ports_count
        self._switch_config = self._config["models"][self._model]["oids"]
    
    async def get_switch_info(self, include_oids: list[str]) -> dict[str, Any]:
        return await self._get(self._filter_request_config(self._switch_config["switch"], include_oids))
    
    async def get_vlan_static_table(self) -> defaultdict[int, dict[str, Any]]:
        def parse_vlan_id(oid: str) -> int:
            return int(oid.rpartition(".")[2])
        
        def parse_assignes_ports(octet_string: str) -> set[str]:
            num_val = int(octet_string, 16)
            return {i + 1 for i in range(self._ports_count) if (num_val >> (63 - i)) & 1}
        
        results = defaultdict(dict)
        
        for oid, vlan_name in await self._bulk_walk(self._switch_config["vlan"]["name"]):
            results[parse_vlan_id(oid)]["vlan_name"] = vlan_name
        
        for oid, octet_string in await self._bulk_walk(self._switch_config["vlan"]["egress_ports"]):
            results[parse_vlan_id(oid)]["tagged_ports"] = parse_assignes_ports(octet_string)
        
        for oid, octet_string in await self._bulk_walk(self._switch_config["vlan"]["untagged_ports"]):
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

        mac_port = await self._bulk_walk(self._switch_config["fdb"]["port"])

        for oid, port in mac_port:
            vlan_id, mac = parse_vlan_id_mac(oid, self._switch_config["fdb"]["port"]["oid"])
            results[vlan_id][mac] = {"port": port}
        
        status_port = await self._bulk_walk(self._switch_config["fdb"]["status"])

        for oid, status in status_port:
            vlan_id, mac = parse_vlan_id_mac(oid, self._switch_config["fdb"]["status"]["oid"])
            results[vlan_id][mac]["status"] = status

        return results

    async def get_port_diagnostics(self, include_oids: list[str]) -> dict[str, Any]:
        return await self._get(self._filter_request_config(self._switch_config["port"], include_oids))

    @override
    def _render_oid(self, oid: str) -> str:
        return oid.format(port=self._port)
    