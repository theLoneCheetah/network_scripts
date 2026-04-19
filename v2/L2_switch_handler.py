#!/usr/bin/python3
import asyncio
from typing import Any, Self
from collections import defaultdict
from pysnmp.hlapi.v3arch.asyncio import *
from L2_switch_client import L2SwitchClient
from const import SNMP

class L2SwitchHandler:
    _port: int
    _client: L2SwitchClient

    def __init__(self, port: int) -> None:
        self._port = port
    
    @classmethod
    async def create(cls, ipaddress: str, port: int) -> Self:
        self = cls(port)
        self._client = await L2SwitchClient.create(ipaddress, port)
        return self

    async def scan_available_mibs(self) -> dict[str, dict[str, Any]]:
        return await self._client.scan_available_mibs()
    
    async def get_default_gateway(self) -> dict[str, str]:
        include_oids = ["default_gateway"]
        return await self._client.get_switch_info(include_oids)
    
    async def get_dhcp_relay(self) -> dict[str, Any]:
        return await self._client.get_dhcp_relay()
    
    async def get_vlan_static_table(self) -> defaultdict[int, dict[str, Any]]:
        return await self._client.get_vlan_static_table()
    
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
    
    async def get_fdb_table(self) -> defaultdict[int, dict[str, dict[str, Any]]]:
        return await self._client.get_fdb_table()
    
    async def get_mac_addresses_on_port(self) -> defaultdict[str, dict[int, dict[str, str]]]:
        fdb_table = await self.get_fdb_table()
        result = defaultdict(dict)

        for vlan_id, mac_list in fdb_table.items():
            for mac, mac_info in mac_list.items():
                if mac_info["port"] == self._port and mac_info["status"] not in {"invalid" , "self"}:
                    result[mac][vlan_id] = {"status": mac_info["status"]}
        
        return result
    
    async def get_cable_diagnostics_port(self) -> dict[str, Any]:
        return await self._client.get_cable_diagnostics_port()
    
    async def get_port_info(self) -> dict[str, str]:
        include_oids = ["admin_state", "speed_duplex_settings", "link_status", "speed_duplex_status"]
        result = await self._client.get_port_diagnostics(include_oids)

        result["link_speed_duplex_status"] = "link_down" if result["link_status"] != "link_pass" else result["speed_duplex_status"]
        del result["link_status"]
        del result["speed_duplex_status"]

        return result
    
    async def get_port_security_on_port(self) -> dict[str, Any]:
        include_oids = ["port_security_max_learning_addresses", "port_security_lock_address_mode", "port_security_admin_state"]
        return await self._client.get_port_diagnostics(include_oids)
    
    async def get_utilization_on_port(self) -> dict[str, int]:
        include_oids = ["utilization_tx_frames", "utilization_rx_frames", "utilization_percentage"]
        return await self._client.get_port_diagnostics(include_oids)
    
    async def get_traffic_control_on_port(self) -> dict[str, int]:
        include_oids = ["traffic_control_threshold", "traffic_control_broadcast_status", "traffic_control_multicast_status", "traffic_control_unicast_status",
                        "traffic_control_action_status", "traffic_control_count_down", "traffic_control_time_interval"]
        return await self._client.get_port_diagnostics(include_oids)