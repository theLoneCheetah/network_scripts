#!/usr/bin/python3
import asyncio
from time import perf_counter
from pprint import pprint
from pysnmp.hlapi.v3arch.asyncio import *
from const import SNMP
from snmp_exceptions import SNMPTransportError
from L2_switch_handler import L2SwitchHandler

async def switch_config_example(switch_handler: L2SwitchHandler) -> None:
    # save and reboot
    # await switch_handler.perform_save({"save_action": "all"})
    # await switch_handler.perform_system_reboot({"system_reboot_mode": "reboot"})

    # network config
    # network_parameters = await switch_handler.get_network_parameters()
    # pprint(network_parameters, sort_dicts=False)
    # await switch_handler.set_network_parameters({"ip": network_parameters["ip"]})
    pprint(await switch_handler.get_network_parameters(), sort_dicts=False)
    
    # current time config, sntp should be disabled
    # res = await switch_handler.get_current_time()
    # print(res)
    # await switch_handler.set_current_time(res)
    # res = await switch_handler.get_current_time()
    # print(res)

async def trusted_host_config_example(switch_handler: L2SwitchHandler) -> None:
    # delete all
    # trusted_hosts = await switch_handler.get_trusted_hosts()
    # pprint(trusted_hosts, sort_dicts=False)
    # await switch_handler.delete_all_trusted_host()
    # pprint(await switch_handler.get_trusted_hosts(), sort_dicts=False)
    
    # await asyncio.sleep(3)
    
    # add all
    # for host in trusted_hosts.values():
    #     await switch_handler.add_trusted_host({"ip": host["ip"], "mask": host["mask"]})
    # pprint(await switch_handler.get_trusted_hosts(), sort_dicts=False)
    
    # await asyncio.sleep(3)

    # add and delete one
    # await switch_handler.add_trusted_host({"ip": "10.132.0.0", "mask": "255.255.255.128"})
    # pprint(await switch_handler.get_trusted_hosts(), sort_dicts=False)
    # await switch_handler.delete_trusted_host({"host_index": 4})
    pprint(await switch_handler.get_trusted_hosts(), sort_dicts=False)

async def acl_config_example(switch_handler: L2SwitchHandler) -> None:
    # # ethernet
    # await switch_handler.create_acl_ethernet_mask({
    #     "profile_id": 140,
    #     # "advanced_params": {
    #     #     "source_mac_mask": "00-FF-FF-00-00-00",
    #     #     "destination_mac_mask": "00-00-00-00-00-00",
    #     #     "use_vlan": "enabled",
    #     #     "use_802_1p": "enabled",
    #     #     "use_ethernet_type": "enabled"
    #     # }
    #     "source_mac_false_check_state": True
    # })
    # await asyncio.sleep(3)
    # await switch_handler.add_acl_ethernet_rule({
    #     "profile_id": 140,
    #     "access_id": 1,
    #     # "advanced_params": {
    #     #     "vlan_name": "default",
    #     #     "source_mac": "00-00-AA-1A-00-00",
    #     #     "destination_mac": "00-00-AA-1A-00-00",
    #     #     "check_802_1p": 4,
    #     #     "ethernet_type": "0x0806",
    #     #     "permit": "deny",
    #     #     "local_priority": 3,
    #     #     "rx_rate": 64
    #     # },
    #     "deny_any_frame": True,
    #     "ports": {20}
    # })
    # await asyncio.sleep(3)
    # await switch_handler.delete_acl_ethernet_rule({"profile_id": 140, "access_id": 1})
    # await asyncio.sleep(3)
    # await switch_handler.delete_acl_ethernet_mask({"profile_id": 140})
    
    # await asyncio.sleep(3)
    
    # # packet content
    # await switch_handler.create_acl_packet_content_mask({
    #     "profile_id": 140,
    #     # "advanced_params": {
    #     #     "offset_masks": {
    #     #         "offset_16_31": "0x00000000000000000000ffffffff0000",
    #     #         "offset_32_47": "0x0000000000000000ffffffffffff0000"
    #     #     }
    #     #     # "general_mask": "0x0000000000000000000000000000000000000000000000000000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    #     #     # "fully_inspected_bytes": {26, 27, 28, 29}
    #     # }
    #     "ipv4_arp_check_state": "ipv4"
    # })
    # await asyncio.sleep(3)
    # await switch_handler.add_acl_packet_content_rule({
    #     "profile_id": 140,
    #     "access_id": 1,
    #     # "advanced_params": {
    #     #     "offsets": {
    #     #         40: "0x88ff11ff",
    #     #         44: "0xffffffff",
    #     #         26: "0x0a5a5a5a"
    #     #     },
    #     #     "local_priority": 5,
    #     #     "rx_rate": 100,
    #     #     "permit": "permit"
    #     # },
    #     "custom_params": {
    #         "ipv4_arp_check_state": "ipv4",
    #         "source_ip": SNMP.DEFAULT_IP
    #     },
    #     "ports": {20}
    # })
    # await asyncio.sleep(3)
    # await switch_handler.delete_acl_packet_content_rule({"profile_id": 140, "access_id": 1})
    # await asyncio.sleep(3)
    # await switch_handler.delete_acl_packet_content_mask({"profile_id": 140})

    pprint(await switch_handler.get_acl_all(), sort_dicts=False)

async def vlan_config_example(switch_handler: L2SwitchHandler) -> None:
    # vlan = {"vlan_id": 2, "vlan_name": "vlan2"}
    # await switch_handler.create_vlan(vlan)
    # await asyncio.sleep(3)
    # await switch_handler.rename_vlan({"vlan_id": 2, "vlan_name": "vlan222"})
    # await asyncio.sleep(3)
    # await switch_handler.add_vlan_on_ports({"vlan_id": vlan["vlan_id"], "portlist": {21,22}, "status": "untagged"})
    # await asyncio.sleep(3)
    # await switch_handler.add_vlan_on_ports({"vlan_id": vlan["vlan_id"], "portlist": {23,24}, "status": "tagged"})
    # await asyncio.sleep(3)
    # await switch_handler.delete_vlan_from_ports({"vlan_id": vlan["vlan_id"], "portlist": {22,24}})
    # await asyncio.sleep(3)
    # await switch_handler.delete_vlan({"vlan_id": vlan["vlan_id"]})

    pprint(await switch_handler.get_vlan_static_table(), sort_dicts=False)

async def fdb_flood_fdb_example(switch_handler: L2SwitchHandler) -> None:
    # fdb
    # pprint(await switch_handler.get_fdb_table(), sort_dicts=False)
    # await switch_handler.clear_fdb_all()
    # await asyncio.sleep(3)
    # pprint(await switch_handler.get_fdb_table(), sort_dicts=False)
    # await asyncio.sleep(3)
    # pprint(await switch_handler.get_fdb_on_port(), sort_dicts=False)
    # await switch_handler.clear_fdb_on_port()
    # await asyncio.sleep(3)
    # pprint(await switch_handler.get_fdb_on_port(), sort_dicts=False)

    # flood fdb
    # pprint(await switch_handler.get_flood_fdb(), sort_dicts=False)
    # await switch_handler.clear_flood_fdb()
    # await asyncio.sleep(3)
    # pprint(await switch_handler.get_flood_fdb(), sort_dicts=False)
    # await switch_handler.set_flood_fdb({"state": "disabled"})
    # await asyncio.sleep(3)
    # pprint(await switch_handler.get_flood_fdb(), sort_dicts=False)
    # await switch_handler.set_flood_fdb({"state": "enabled"})
    # await asyncio.sleep(3)
    pprint(await switch_handler.get_flood_fdb(), sort_dicts=False)

async def dhcp_relay_config_example(switch_handler: L2SwitchHandler) -> None:
    # settings = await switch_handler.get_dhcp_relay()
    # server = list(settings["ipif_servers"]["System"])[0]
    # await switch_handler.set_dhcp_relay({"option82_remote_id_type": "default", "option82_policy": "replace", "time_threshold": 0})
    # await asyncio.sleep(3)
    # await switch_handler.delete_dhcp_server_for_ipif({"ipif_name": "System", "server": server})
    # await asyncio.sleep(3)
    # await switch_handler.add_dhcp_server_for_ipif({"ipif_name": "System", "server": server})
    pprint(await switch_handler.get_dhcp_relay(), sort_dicts=False)

async def port_management_example(switch_handler: L2SwitchHandler) -> None:
    pprint(await switch_handler.get_port_status(), sort_dicts=False)
    pprint(await switch_handler.get_port_management(), sort_dicts=False)
    await switch_handler.set_port_management({"admin_state": "disabled"})
    pprint(await switch_handler.get_port_management(), sort_dicts=False)
    await switch_handler.set_port_management({"admin_state": "enabled"})
    pprint(await switch_handler.get_port_management(), sort_dicts=False)

async def port_security_config_example(switch_handler: L2SwitchHandler) -> None:
    print(await switch_handler.get_port_security_on_port())
    await switch_handler.set_port_security_on_port({"admin_state": "disable", "lock_address_mode": "delete_on_timeout"})
    print(await switch_handler.get_port_security_on_port())

    # await switch_handler.clear_port_security_on_port()
    # config = {"mac_addresses_list": [{"vlan_id": 11, "port": 2, "mac_address": "40-AE-30-0E-54-C5"}]}
    # await switch_handler.clear_port_security_exact_mac_addresses(config)

async def main() -> None:
    ipaddress = SNMP.TEST_3028
    port = 2

    start_time = perf_counter()

    switch_handler = await L2SwitchHandler.create(ipaddress, port)

    await port_management_example(switch_handler)

    print("Overall time:", perf_counter() - start_time)

asyncio.run(main())
