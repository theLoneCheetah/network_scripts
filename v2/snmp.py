#!/usr/bin/python3
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from const import SNMP


async def run():
    snmpEngine = SnmpEngine()

    iterator = get_cmd(
        snmpEngine,
        CommunityData(SNMP.READ_ONLY),
        await UdpTransportTarget.create((SNMP.TEST_3028, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.1.25.100")),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.2.25.100")),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.4.25.100")),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.5.25.100")),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.1.25.101")),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.2.25.101")),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.4.25.101")),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.5.25.101")),
    )

    errorIndication, errorStatus, errorIndex, varBinds = await iterator
    
    for varBind in varBinds:
        print(varBind.prettyPrint())
    


    iterator = get_cmd(
        snmpEngine,
        CommunityData(SNMP.READ_ONLY),
        await UdpTransportTarget.create((SNMP.TEST_3028, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.5.25.100")),
    )

    errorIndication, errorStatus, errorIndex, varBinds = await iterator
    
    for varBind in varBinds:
        print(varBind.prettyPrint())

    iterator = get_cmd(
        snmpEngine,
        CommunityData(SNMP.READ_ONLY),
        await UdpTransportTarget.create((SNMP.TEST_3028, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(".1.3.6.1.4.1.171.11.63.6.2.2.1.1.5.25.101")),
    )

    errorIndication, errorStatus, errorIndex, varBinds = await iterator
    
    for varBind in varBinds:
        print(varBind.prettyPrint())

    snmpEngine.close_dispatcher()

asyncio.run(run())