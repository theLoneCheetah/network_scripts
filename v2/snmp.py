#!/usr/bin/python3
from time import perf_counter
import asyncio
import yaml
from pysnmp.hlapi.v3arch.asyncio import *
from const import SNMP


async def port_diagnostics(port):
    with open("v2/oid.yaml", "r") as F:
        config = yaml.safe_load(F)
    
    Engine = SnmpEngine()
    Community = CommunityData(SNMP.READ_ONLY)
    Transport = await UdpTransportTarget.create((SNMP.TEST_3028, 161))
    Context = ContextData()

    request_data = [{"command": command,
                    **data}
                    for command, data in config["models"]["DES-3028"]["oids"].items()]
    
    oid_objects = [ObjectType(ObjectIdentity(request["oid"].format(port=port))) for request in request_data]
    
    start_time = perf_counter()

    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        Engine,
        Community,
        Transport,
        Context,
        *oid_objects
    )

    print(perf_counter() - start_time)

    for data, varBind in zip(request_data, varBinds):
        print(data["command"], end="; ")
        if data["type"] == "integer":
            print(data["values"][int(varBind[1].prettyPrint())])
        else:
            print(varBind[1].prettyPrint())
    
    Engine.close_dispatcher()

async def main():
    port = 2

    task1 = asyncio.create_task(port_diagnostics(port))

    await asyncio.gather(task1)

asyncio.run(main())
