#!/usr/bin/python3
from time import perf_counter
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from collections import defaultdict
from const import SNMP
from schemas import PortSecurityConfig
from L2_switch_handler import L2SwitchHandler

async def vlan_config_example(switch_handler: L2SwitchHandler) -> None:
    vlan = {"vlan_id": 2, "vlan_name": "vlan2"}
    await switch_handler.create_vlan({"vlan": vlan})
    await asyncio.sleep(5)
    await switch_handler.add_vlan_on_ports({"vlan_id": vlan["vlan_id"], "portlist": {21,22}, "status": "untagged"})
    await asyncio.sleep(5)
    await switch_handler.add_vlan_on_ports({"vlan_id": vlan["vlan_id"], "portlist": {23,24}, "status": "tagged"})
    await asyncio.sleep(5)
    await switch_handler.delete_vlan_from_ports({"vlan_id": vlan["vlan_id"], "portlist": {22,24}})
    await asyncio.sleep(5)
    await switch_handler.delete_vlan({"vlan_id": vlan["vlan_id"]})

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

    res = await switch_handler.get_current_time()
    print(res)
    await switch_handler.set_current_time(res)
    res = await switch_handler.get_current_time()
    print(res)

    # network_parameters = await switch_handler.get_network_parameters()
    # ip, mask, default_gateway, management_vlan_id = network_parameters.values()
    # print(network_parameters)
    # await switch_handler.set_network_parameters({"ip": ip, "mask": "255.255.255.0", "default_gateway": default_gateway})
    # network_parameters = await switch_handler.get_network_parameters()
    # print(network_parameters)

    print("Overall time:", perf_counter() - start_time)

asyncio.run(main())
