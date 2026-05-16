#!/usr/bin/python3
import asyncio
from typing import Any, Self
from collections import defaultdict
from datetime import datetime
from pydantic import ValidationError
from pysnmp.hlapi.v3arch.asyncio import *
from L2_switch_client import L2SwitchClient
from const import SNMP
from snmp_exceptions import *
from schemas import *

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

    ### MIB MODULES ###

    async def scan_available_mibs(self) -> dict[str, dict[str, Any]]:
        return await self._client.scan_available_mibs()
    
    ### SWITCH INFO ###

    async def get_default_gateway(self) -> dict[str, str]:
        include_oids = ["default_gateway"]
        return await self._client.get_switch_info(include_oids)
    
    async def get_current_time(self) -> dict[str, datetime]:
        return await self._client.get_current_time()
    
    #### DHCP RELAY ###

    async def get_dhcp_relay(self) -> dict[str, Any]:
        return await self._client.get_dhcp_relay()
    
    ### VLAN ###

    async def get_vlan_static_table(self) -> defaultdict[int, dict[str, Any]]:
        return await self._client.get_vlan_static_table()
    
    async def get_vlan_on_port(self) -> defaultdict[str, set[int]]:
        return await self._client.get_vlan_on_port()
    
    async def create_vlan(self, vlan: dict[str, Any]) -> None:
        request = {"vlan": vlan}
        response = await self._client.create_vlan(request)
        print(response.value[1])
    
    async def delete_vlan(self, vlan: dict[str, Any]) -> None:
        request = {"vlan": vlan}
        response = await self._client.delete_vlan(request)
        print(response.value[1])

    async def add_vlan_on_ports(self, portlist: set[int], vlan: dict[str, Any], status: str) -> None:
        request = {"portlist": portlist, "vlan": vlan, "status": status}
        response = await self._client.add_vlan_on_ports(request)
        print(response.value[1])

    async def delete_vlan_from_ports(self, portlist: set[int], vlan: dict[str, Any]) -> None:
        request = {"portlist": portlist, "vlan": vlan}
        response = await self._client.delete_vlan_from_ports(request)
        print(response.value[1])
    
    ### MAC ADDRESS ###

    async def get_fdb_table(self) -> defaultdict[int, dict[str, dict[str, Any]]]:
        return await self._client.get_fdb_table()
    
    async def get_mac_addresses_on_port(self) -> defaultdict[str, dict[int, dict[str, str]]]:
        return await self._client.get_mac_addresses_on_port()
    
    ### FLOOD FDB ###
    
    async def get_flood_fdb_state(self) -> dict[str, str]:
        return await self._client.get_flood_fdb_state()
    
    async def set_flood_fdb_state(self, state: str) -> None:
        request = {"state": state}
        response = await self._client.set_flood_fdb_state(request)
        print(response.value[1])
    
    async def get_flood_fdb_table(self) -> dict[int, dict[str, dict[str, int]]]:
        return await self._client.get_flood_fdb_table()
    
    async def clear_flood_fdb_table(self) -> None:
        response = await self._client.clear_flood_fdb_table()
        print(response.value[1])
    
    ### PORT MANAGEMENT AND INFO ###

    async def get_port_info(self) -> dict[str, str]:
        include_oids = ["admin_state", "speed_duplex_settings", "link_status", "speed_duplex_status"]
        result = await self._client.get_port_diagnostics(include_oids)

        result["link_speed_duplex_status"] = "link_down" if result["link_status"] != "link_pass" else result["speed_duplex_status"]
        del result["link_status"]
        del result["speed_duplex_status"]

        return result
    
    async def get_port_management(self) -> dict[str, Any]:
        return await self._client.get_port_management()
    
    async def set_port_management(self, config: dict[str, Any]) -> None:
        try:
            request = PortManagementConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_port_management(request)
        print(response.value[1])
    
    ### CABLE DIAGNOSTICS ### 

    async def get_cable_diagnostics_port(self) -> dict[str, Any]:
        return await self._client.get_cable_diagnostics_port()
    
    ### PORT SECURITY ###

    async def get_port_security_on_port(self) -> dict[str, Any]:
        return await self._client.get_port_security_on_port()
    
    async def set_port_security_on_port(self, config: dict[str, Any]) -> None:
        try:
            request = PortSecurityConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_port_security_on_port(request)
        print(response.value[1])
    
    async def clear_port_security_on_port(self) -> None:
        response = await self._client.clear_port_security_on_port()
        print(response.value[1])
    
    async def clear_port_security_exact_mac_address(self, mac_list: list[dict[str, Any]]) -> None:
        response = await self._client.clear_port_security_exact_mac_address(mac_list)
        print(response.value[1])
    
    ### LOOPBACK DETECTION ###

    async def get_loopdetect_on_port(self) -> dict[str, str]:
        return await self._client.get_loopdetect_on_port()
    
    async def set_loopdetect_state_on_port(self, state: str) -> None:
        request = {"state": state}
        response = await self._client.set_loopdetect_state_on_port(request)
        print(response.value[1])

    ### PORT UTILIZATION ###

    async def get_utilization_on_port(self) -> dict[str, int]:
        return await self._client.get_utilization_on_port()
    
    ### BANDWIDTH CONTROL ###

    async def get_bandwidth_control_on_port(self) -> dict[str, Any]:
        return await self._client.get_bandwidth_control_on_port()
    
    async def set_bandwidth_control_on_port(self, config: dict[str, Any]) -> None:
        try:
            request = BandwidthControlConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_bandwidth_control_on_port(request)
        print(response.value[1])
    
    ### TRAFFIC CONTROL ###
    
    async def get_traffic_control_on_port(self) -> dict[str, int]:
        return await self._client.get_traffic_control_on_port()
    
    async def set_traffic_control_on_port(self, config: dict[str, Any]) -> None:
        try:
            request = TrafficControlConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_traffic_control_on_port(request)
        print(response.value[1])
    
    ### TRAFFIC SEGMENTATION ###

    async def get_traffic_segmentation_forward_ports_for_port(self) -> dict[str, set[int]]:
        return await self._client.get_traffic_segmentation_forward_ports_for_port()

    async def set_traffic_segmentation_forward_ports_for_port(self, portlist: set[int]) -> None:
        request = {"portlist": portlist}
        response = await self._client.set_traffic_segmentation_forward_ports_for_port(request)
        print(response.value[1])