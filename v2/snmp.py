#!/usr/bin/python3
from time import perf_counter
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from const import SNMP
from L2_switch_client import L2SwitchClient


async def main():
    port = 2
    model = "DES-3028"
    ipaddress = SNMP.TEST_3028

    include_oids_switch_info = ["ip", "msak", "default_gateway"]
    include_oids_port_diagnostics = ["admin_state", "speed_duplex_settings", "link_status", "speed_duplex_status"]

    start_time = perf_counter()

    switch_client = L2SwitchClient(ipaddress, port, model)

    task1 = asyncio.create_task(switch_client.get_switch_info(include_oids_switch_info))
    task2 = asyncio.create_task(switch_client.get_port_diagnostics(include_oids_port_diagnostics))
    task3 = asyncio.create_task(switch_client.get_fdb_table())

    results = await asyncio.gather(task1, task2, task3)

    print(results)
    print("Overall time:", perf_counter() - start_time)

async def test_walk():
    result = []
    start_oid = "1.3.6.1.2.1.17.7.1.2.2.1"

    start_time = perf_counter()

    async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
        SnmpEngine(),
        CommunityData(SNMP.READ_ONLY),
        await UdpTransportTarget.create((SNMP.TEST_3028, 161)),
        ContextData(),
        0, 49,
        ObjectType(ObjectIdentity(start_oid)),
        lexicographicMode=False
    ):
        for varBind in varBinds:
            oid = str(varBind[0])
            result.append((oid, int(varBind[1])))

    print(result)
    print(len(result))
    print(perf_counter() - start_time)

asyncio.run(main())
#asyncio.run(test_walk())
