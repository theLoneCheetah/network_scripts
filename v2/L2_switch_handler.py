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

    async def perform_system_reboot(self, config: RequestData) -> None:
        try:
            request = SystemRebootConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.perform_system_reboot(request)
        print(response.value[1])

    async def perform_save(self, config: RequestData) -> None:
        try:
            request = SaveConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.perform_save(request)
        print(response.value[1])
    
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
    
    ### TRUSTED HOST ###

    async def get_trusted_hosts(self) -> ResponseData:
        return await self._client.get_trusted_hosts()
    
    async def add_trusted_host(self, config: RequestData) -> None:
        try:
            request = AddTrustedHostConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.add_trusted_host(request)
        print(response.value[1])
    
    async def delete_trusted_host(self, config: RequestData) -> None:
        try:
            request = DeleteTrustedHostConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.delete_trusted_host(request)
        print(response.value[1])

    async def delete_all_trusted_host(self) -> None:
        response = await self._client.delete_all_trusted_host()
        print(response.value[1])
    
    ### ACL ###
    
    async def get_acl_ethernet(self) -> ResponseData:
        return await self._client.get_acl_ethernet()

    async def get_acl_packet_content(self) -> ResponseData:
        return await self._client.get_acl_packet_content()

    async def get_acl_all(self) -> ResponseData:
        return await self._client.get_acl_all()

    async def get_acl_for_port(self) -> ResponseData:
        return await self._client.get_acl_for_port()
    
    async def create_acl_ethernet_mask(self, config: RequestData) -> None:
        try:
            request = CreateAclEthernetMaskConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.create_acl_ethernet_mask(request)
        print(response.value[1])
    
    async def delete_acl_ethernet_mask(self, config: RequestData) -> None:
        try:
            request = DeleteAclMaskConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.delete_acl_ethernet_mask(request)
        print(response.value[1])
    
    async def add_acl_ethernet_rule(self, config: RequestData) -> None:
        try:
            request = AddAclEthernetRuleConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.add_acl_ethernet_rule(request)
        print(response.value[1])
    
    async def delete_acl_ethernet_rule(self, config: RequestData) -> None:
        try:
            request = DeleteAclRuleConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.delete_acl_ethernet_rule(request)
        print(response.value[1])
    
    async def create_acl_packet_content_mask(self, config: RequestData) -> None:
        try:
            request = CreateAclPacketContentMaskConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.create_acl_packet_content_mask(request)
        print(response.value[1])
    
    async def delete_acl_packet_content_mask(self, config: RequestData) -> None:
        try:
            request = DeleteAclMaskConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.delete_acl_packet_content_mask(request)
        print(response.value[1])
    
    async def add_acl_packet_content_rule(self, config: RequestData) -> None:
        try:
            request = AddAclPacketContentRuleConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.add_acl_packet_content_rule(request)
        print(response.value[1])
    
    async def delete_acl_packet_content_rule(self, config: RequestData) -> None:
        try:
            request = DeleteAclRuleConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.delete_acl_packet_content_rule(request)
        print(response.value[1])
    
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
    
    # async def rename_vlan(self, config: RequestData) -> SNMPResponseCode:
    #     try:
    #         request = RenameVlanConfig(**config).model_dump(exclude_none=True)
    #     except ValidationError:
    #         print(SNMPResponseCode.INVALID_DATA.value[1])
    #         return
        
    #     response = await self._client.rename_vlan(request)
    #     print(response.value[1])
    
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
    
    ### FDB ###

    async def get_fdb_table(self) -> defaultdict[int, dict[str, dict[str, Any]]]:
        return await self._client.get_fdb_table()
    
    async def get_fdb_on_port(self) -> ResponseData:
        return await self._client.get_fdb_on_port()
    
    async def clear_fdb_on_port(self) -> None:
        response = await self._client.clear_fdb_on_port()
        print(response.value[1])

    async def clear_fdb_all(self) -> None:
        response = await self._client.clear_fdb_all()
        print(response.value[1])
    
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
    
    #### DHCP RELAY ###

    async def get_dhcp_relay(self) -> ResponseData:
        return await self._client.get_dhcp_relay()
    
    async def set_dhcp_relay(self, config: RequestData) -> None:
        try:
            request = DhcpRelayConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.set_dhcp_relay(request)
        print(response.value[1])
    
    async def add_dhcp_servers_for_ipif(self, config: RequestData) -> None:
        try:
            request = ManageDhcpServersForIpifConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.add_dhcp_servers_for_ipif(request)
        print(response.value[1])
    
    async def delete_dhcp_servers_for_ipif(self, config: RequestData) -> None:
        try:
            request = ManageDhcpServersForIpifConfig(**config).model_dump(exclude_none=True)
        except ValidationError:
            print(SNMPResponseCode.INVALID_DATA.value[1])
            return
        
        response = await self._client.delete_dhcp_servers_for_ipif(request)
        print(response.value[1])
    
    ### ARP ###

    async def get_arp_table(self) -> ResponseData:
        return await self._client.get_arp_table()
    
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

    async def get_cable_diagnostics_for_port(self) -> ResponseData:
        return await self._client.get_cable_diagnostics_for_port()
    
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
    
    ### PORT STATISCTICS ###

    async def get_rx_tx_megabit_speed_on_port(self) -> ResponseData:
        return await self._client.get_rx_tx_megabit_speed_on_port()

    async def get_rx_tx_packets_all_types_on_port(self) -> ResponseData:
        return await self._client.get_rx_tx_packets_all_types_on_port()

    async def get_all_packet_statistics_on_port(self) -> ResponseData:
        return await self._client.get_all_packet_statistics_on_port()

    async def get_crc_errors_on_port(self) -> ResponseData:
        return await self._client.get_crc_errors_on_port()

    async def clear_all_counters(self) -> None:
        response = await self._client.clear_all_counters()
        print(response.value[1])