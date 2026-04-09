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
    _switch_config: dict[str, Any]
    
    def __init__(self, ipaddress: str, port: int, model: str) -> None:
        super().__init__(ipaddress)
        self._port = port
        self._model = model
        self._switch_config = self._config["models"][self._model]["oids"]
    
    async def get_switch_info(self, include_oids: list[str]) -> dict[str, Any]:
        return await self._get(self._filter_request_config(self._switch_config["switch"], include_oids))
    
    async def get_fdb_table(self) -> defaultdict[int, dict[str, dict[str, Any]]]:
        results = defaultdict(dict)

        mac_port = await self._bulk_walk(self._switch_config["fdb"]["port"])

        for oid, port in mac_port:
            vlan_id_mac = oid.partition(self._switch_config["fdb"]["port"]["oid"] + ".")[2]
            vlan_id, mac = vlan_id_mac.split(".", 1)
            vlan_id = int(vlan_id)
            mac = "-".join([f"{int(octet):02X}" for octet in mac.split(".")])
            results[vlan_id][mac] = {"port": port}
        
        status_port = await self._bulk_walk(self._switch_config["fdb"]["status"])

        for oid, status in status_port:
            vlan_id_mac = oid.partition(self._switch_config["fdb"]["status"]["oid"] + ".")[2]
            vlan_id, mac = vlan_id_mac.split(".", 1)
            vlan_id = int(vlan_id)
            mac = "-".join([f"{int(octet):02X}" for octet in mac.split(".")])
            results[vlan_id][mac]["status"] = status

        return results

    async def get_port_diagnostics(self, include_oids: list[str]) -> dict[str, Any]:
        return await self._get(self._filter_request_config(self._switch_config["port"], include_oids))

    @override
    def _render_oid(self, oid: str) -> str:
        return oid.format(port=self._port)
    