#!/usr/bin/python3
from time import perf_counter
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from collections import defaultdict
from const import SNMP
from L2_switch_handler import L2SwitchHandler

async def main():
    ipaddress = SNMP.TEST_3028
    port = 2

    start_time = perf_counter()

    switch_handler = await L2SwitchHandler.create(ipaddress, port)
    
    # vlan = {"vlan_id": 2, "vlan_name": "vlan2"}
    # await switch_handler.create_vlan(vlan)
    # await asyncio.sleep(5)
    # await switch_handler.add_vlan_on_ports({21,22}, vlan, "untagged")
    # await asyncio.sleep(5)
    # await switch_handler.add_vlan_on_ports({23,24}, vlan, "tagged")
    # await asyncio.sleep(5)
    # await switch_handler.add_vlan_on_ports({22}, vlan, "tagged")
    # await asyncio.sleep(5)
    # await switch_handler.delete_vlan_from_ports({22,24}, vlan)
    # await asyncio.sleep(5)
    # await switch_handler.delete_vlan(vlan)

    print(await switch_handler.get_vlan_static_table())

    # task1 = asyncio.create_task(switch_handler.get_default_gateway())
    # task2 = asyncio.create_task(switch_handler.get_port_info())
    # task3 = asyncio.create_task(switch_handler.get_mac_addresses_on_port())
    # task4 = asyncio.create_task(switch_handler.get_vlan_on_port())
    # task5 = asyncio.create_task(switch_handler.get_cable_diagnostics_port())
    # task6 = asyncio.create_task(switch_handler.get_dhcp_relay())

    # results = await asyncio.gather(task1, task2, task3, task4, task5, task6)

    # print(results)
    print("Overall time:", perf_counter() - start_time)

asyncio.run(main())
