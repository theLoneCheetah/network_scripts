#!/usr/bin/python3
import asyncio
from time import perf_counter
from L2_switch_client import L2SwitchClient
from test_db import TestDatabaseManager
from snmp_exceptions import SNMPTransportError

def any_database_test() -> None:
    test_database = TestDatabaseManager()
    print(test_database.get_users_last_today_from_pseudo_L3())

def get_switch_ip_addresses_by_model(model: str) -> set[str]:
    assert_switch_models = set([model])

    match model:
        # L2
        case "DES-3028":
            database_model_names = {"3028", "3028-M"}
        case "DES-3052":
            database_model_names = {"3052"}
        case "DES-3200-28":
            database_model_names = {"3200-28"}
        case "DES-3526":
            database_model_names = {"3526"}
        case "DGS-3000-24TC":
            database_model_names = {"3000-24TC"}
        case "DGS-3000-26TC":
            database_model_names = {"3000-26TC"}
        case "DGS-3200-24":
            database_model_names = {"3200-24"}
        case "DGS-1210-28/ME/A2":
            database_model_names = {"DGS-1210-28-A2"}
        case "DGS-1210-28/ME":
            database_model_names = {"DGS-1210-28", "DGS-1210-28P"}
            assert_switch_models = {"DGS-1210-28/ME/B1", "DGS-1210-28/ME/B2"}
        case "DGS-1210-52/ME/B1":
            database_model_names = {"DGS-1210-52P"}
        # L2+
        case "DGS-3120-24TC":
            database_model_names = {"3120-24TC"}
        case "DGS-3120-24SC":
            database_model_names = {"3120-24SC"}
        # L2 fiber
        case "DGS-3100-24TG":
            database_model_names = {"3100-24"}
        case "DGS-1210-28XS/ME/B1":
            database_model_names = {"DGS-1210-28XSME"}
        case "SNR-S2995G-48FX":
            database_model_names = {"SNR-S2995G-48FX"}
        # L2/L3
        case "DGS-3612":
            database_model_names = {"3612"}
        case "DGS-3627G":
            database_model_names = {"3627G"}
        case "DGS-3620-28TC":
            database_model_names = {"3620-28TC"}
        case "DGS-3620-28SC":
            database_model_names = {"3620-28SC"}
        case "DGS-3630-28SC":
            database_model_names = {"DGS-3630-28SC"}
    
    switch_ip_addresses = set()
    for name in database_model_names:
        switch_ip_addresses.update(TestDatabaseManager().get_switches_by_model(name))
    
    return switch_ip_addresses, assert_switch_models

async def assert_switch_model_by_snmp(model_name: str) -> None:
    switch_ip_addresses, assert_switch_models = get_switch_ip_addresses_by_model(model_name)
    
    start_time = perf_counter()
    count_hundreds = 0
    unavailable_switch_ip_addresses = set()
    
    for ind, ip_address in enumerate(switch_ip_addresses):
        if ind % 100 == 0:
            count_hundreds += 1
            print(f"Hundred number {count_hundreds} started")
        
        try:
            await L2SwitchClient.create(ip_address, assert_switch_models=assert_switch_models)
        except SNMPTransportError:
            print(f"SNMPTransportError: the switch with ip {ip_address} is unavailable")
            unavailable_switch_ip_addresses.add(ip_address)
        except KeyError:
            print(f"Uknown switch model with ip {ip_address}")

    print(f"""---
Model: {model_name}
Number of switches: {len(switch_ip_addresses)}
Overall time: {perf_counter() - start_time}""")

# L2
# DES-3028 ok
# DES-3052 ok
# DES-3200-28 ok
# DES-3526 ok
# DGS-3000-24TC ok
# DGS-3000-26TC ok
# DGS-3200-24 ok
# DGS-1210-28/ME/A2 ok
# DGS-1210-28/ME ok
# DGS-1210-52/ME/B1 ok
# L2+
# DGS-3120-24TC ok
# DGS-3120-24SC ok
# L2 fiber
# DGS-3100-24TG ok
# DGS-1210-28XS/ME/B1 ok
# SNR-S2995G-48FX ok
# L2/L3
# DGS-3612 ok
# DGS-3627G ok
# DGS-3620-28TC ok
# DGS-3620-28SC ok
# DGS-3630-28SC ok
asyncio.run(assert_switch_model_by_snmp("DGS-3630-28SC"))