#!/usr/bin/python3
from time import perf_counter
import asyncio
import yaml
from pysnmp.hlapi.v3arch.asyncio import *
from const import SNMP

async def switch_info():
    with open("v2/oid.yaml", "r") as F:
        config = yaml.safe_load(F)
    
    Engine = SnmpEngine()
    Community = CommunityData(SNMP.READ_ONLY)
    Transport = await UdpTransportTarget.create((SNMP.TEST_3028, 161))
    Context = ContextData()

    request_data = [{"command": command,
                    **data}
                    for command, data in config["models"]["DES-3028"]["oids"]["switch"].items()]
    
    oid_objects = [ObjectType(ObjectIdentity(request["oid"])) for request in request_data]
    
    start_time = perf_counter()
    print("Switch started\n")

    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        Engine,
        Community,
        Transport,
        Context,
        *oid_objects
    )

    print("Switch:", perf_counter() - start_time, "\n")

    for data, varBind in zip(request_data, varBinds):
        print(data["command"], end="; ")
        if data["type"] == "integer" and "values" in data:
            print(data["values"][int(varBind[1].prettyPrint())])
        else:
            print(varBind[1].prettyPrint())
    
    Engine.close_dispatcher()

async def port_diagnostics(port):
    with open("v2/oid.yaml", "r") as F:
        config = yaml.safe_load(F)
    
    Engine = SnmpEngine()
    Community = CommunityData(SNMP.READ_ONLY)
    Transport = await UdpTransportTarget.create((SNMP.TEST_3028, 161))
    Context = ContextData()

    request_data = [{"command": command,
                    **data}
                    for command, data in config["models"]["DES-3028"]["oids"]["port"].items()]
    
    oid_objects = [ObjectType(ObjectIdentity(request["oid"].format(port=port))) for request in request_data]
    
    start_time = perf_counter()
    print("Port started\n")

    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        Engine,
        Community,
        Transport,
        Context,
        *oid_objects
    )

    print("Port:", perf_counter() - start_time, "\n")

    for data, varBind in zip(request_data, varBinds):
        print(data["command"], end="; ")
        if data["type"] == "integer" and "values" in data:
            print(data["values"][int(varBind[1].prettyPrint())])
        else:
            print(varBind[1].prettyPrint())
    
    Engine.close_dispatcher()

async def main():
    port = 2

    start_time = perf_counter()

    task1 = asyncio.create_task(switch_info())
    task2 = asyncio.create_task(port_diagnostics(port))

    await asyncio.gather(task1, task2)

    print("Overall time:", perf_counter() - start_time)

asyncio.run(main())
