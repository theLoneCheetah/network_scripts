#!/usr/bin/python3
import asyncio
from typing import Any, Self
from collections import defaultdict
from datetime import datetime
from pydantic import ValidationError
from pysnmp.hlapi.v3arch.asyncio import *
from L2_switch_client import L2SwitchClient, RequestData, ResponseData
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

    async def scan_available_mibs(self) -> ResponseData:
        return await self._client.scan_available_mibs()
    
    ### SWITCH MANAGEMENT AND INFO ###
    
    async def get_network_parameters(self) -> ResponseData:
        return await self._client.get_network_parameters()
    
    async def set_network_parameters(self, config: RequestData) -> None:
        try:
            request = SwitchNetworkConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_network_parameters(request)
        print(response.value[1])

    async def get_mac_address(self) -> ResponseData:
        return await self._client.get_mac_address()
    
    async def get_ports_number(self) -> ResponseData:
        return await self._client.get_ports_number()
    
    async def get_current_time(self) -> ResponseData:
        return await self._client.get_current_time()
    
    async def set_current_time(self, config: RequestData) -> None:
        try:
            request = CurrentTimeConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_current_time(request)
        print(response.value[1])
    
    async def get_cpu_utilization(self) -> ResponseData:
        return await self._client.get_cpu_utilization()
    
    async def get_dram_utilization(self) -> ResponseData:
        return await self._client.get_dram_utilization()
    
    #### DHCP RELAY ###

    async def get_dhcp_relay(self) -> ResponseData:
        return await self._client.get_dhcp_relay()
    
    ### VLAN ###

    async def get_vlan_static_table(self) -> defaultdict[int, dict[str, Any]]:
        return await self._client.get_vlan_static_table()
    
    async def get_vlan_on_port(self) -> ResponseData:
        return await self._client.get_vlan_on_port()
    
    async def create_vlan(self, config: RequestData) -> None:
        try:
            request = CreateVlanConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.create_vlan(request)
        print(response.value[1])
    
    async def delete_vlan(self, config: RequestData) -> None:
        try:
            request = DeleteVlanConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.delete_vlan(request)
        print(response.value[1])

    async def add_vlan_on_ports(self, config: RequestData) -> None:
        try:
            request = AddVlanOnPortsConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.add_vlan_on_ports(request)
        print(response.value[1])

    async def delete_vlan_from_ports(self, config: RequestData) -> None:
        try:
            request = DeleteVlanFromPortsConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.delete_vlan_from_ports(request)
        print(response.value[1])
    
    ### MAC ADDRESS ###

    async def get_fdb_table(self) -> defaultdict[int, dict[str, dict[str, Any]]]:
        return await self._client.get_fdb_table()
    
    async def get_mac_addresses_on_port(self) -> ResponseData:
        return await self._client.get_mac_addresses_on_port()
    
    ### FLOOD FDB ###
    
    async def get_flood_fdb(self) -> ResponseData:
        return await self._client.get_flood_fdb()
    
    async def set_flood_fdb(self, config: RequestData) -> None:
        try:
            request = FloodFdbConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_flood_fdb(request)
        print(response.value[1])
    
    async def clear_flood_fdb(self) -> None:
        response = await self._client.clear_flood_fdb()
        print(response.value[1])
    
    ### PORT MANAGEMENT AND INFO ###

    async def get_port_status(self) -> ResponseData:
        return await self._client.get_port_status()
    
    async def get_port_management(self) -> ResponseData:
        return await self._client.get_port_management()
    
    async def set_port_management(self, config: RequestData) -> None:
        try:
            request = PortManagementConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_port_management(request)
        print(response.value[1])
    
    ### CABLE DIAGNOSTICS ### 

    async def get_cable_diagnostics_port(self) -> ResponseData:
        return await self._client.get_cable_diagnostics_port()
    
    ### PORT SECURITY ###

    async def get_port_security_on_port(self) -> ResponseData:
        return await self._client.get_port_security_on_port()
    
    async def set_port_security_on_port(self, config: RequestData) -> None:
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
    
    async def clear_port_security_exact_mac_addresses(self, config: RequestData) -> None:
        try:
            request = ClearPortSecurityExactMacAddressesConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.clear_port_security_exact_mac_addresses(request)
        print(response.value[1])
    
    ### LOOPBACK DETECTION ###

    async def get_loopdetect_on_port(self) -> ResponseData:
        return await self._client.get_loopdetect_on_port()
    
    async def set_loopdetect_on_port(self, config: RequestData) -> None:
        try:
            request = LoopdetectConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_loopdetect_on_port(request)
        print(response.value[1])

    ### PORT UTILIZATION ###

    async def get_port_utilization(self) -> ResponseData:
        return await self._client.get_port_utilization()
    
    ### BANDWIDTH CONTROL ###

    async def get_bandwidth_control_on_port(self) -> ResponseData:
        return await self._client.get_bandwidth_control_on_port()
    
    async def set_bandwidth_control_on_port(self, config: RequestData) -> None:
        try:
            request = BandwidthControlConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_bandwidth_control_on_port(request)
        print(response.value[1])
    
    ### TRAFFIC CONTROL ###
    
    async def get_traffic_control_on_port(self) -> ResponseData:
        return await self._client.get_traffic_control_on_port()
    
    async def set_traffic_control_on_port(self, config: RequestData) -> None:
        try:
            request = TrafficControlConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_traffic_control_on_port(request)
        print(response.value[1])
    
    ### TRAFFIC SEGMENTATION ###

    async def get_traffic_segmentation_for_port(self) -> ResponseData:
        return await self._client.get_traffic_segmentation_for_port()

    async def set_traffic_segmentation_for_port(self, config: RequestData) -> None:
        try:
            request = TrafficSegmentationConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_traffic_segmentation_for_port(request)
        print(response.value[1])