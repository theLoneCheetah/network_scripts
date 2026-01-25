#!/usr/bin/python3
import re
import traceback
import signal
import sys
import os
from abc import ABC
from typing import Any, override
from ipaddress import IPv4Address, IPv4Network, AddressValueError
# user's modules
from diag_handler import DiagHandler
from database_manager import DatabaseManager
from base_olt import BaseOLT
from olt_version2 import OLTVersion2
from olt_version3 import OLTVersion3
from L3_switch import L3Switch
from const import Database, Country
from country_alarm import CountryAlarmManager
from base_olt import BaseOLT
from my_exception import ExceptionType, MyException


##### MAIN CLASS TO HANDLE COUNTRY USER DIAGNOSTICS #####

class CountryDiagHandler(DiagHandler):
    # annotations of inherited attributes
    _L2_manager: BaseOLT | None
    _L3_manager: L3Switch | None
    # class attributes annotations
    __print_output: bool
    __ip_correct: bool
    __ip_out_of_country_subnets: bool
    __olt_ip: str
    __eltex_serial: str

    def __init__(self, usernum: int, db_manager: DatabaseManager, record_data: dict[str, Any], inactive_payment: bool, print_output: bool = False) -> None:
        # init with base constructor
        super().__init__(usernum, db_manager, record_data, inactive_payment)

        # L2 and L3 managers
        self._L2_manager = None
        self._L3_manager = None

        # indicate if terminal output needed
        self.__print_output = True


        # attributes for diagnostics of the database record

        # -1 if data from record is incorrect, 0 if empty, 1 if correct
        self._correctly_filled = {}
        
        # flag for main record diagnostics
        self.__ip_correct = False

        # flags for errors in diagnostics of the database record
        self.__ip_out_of_country_subnets = False


        # flags for variables and erros in country alarm
        self.__olt_ip = ""
        self.__eltex_serial = ""


        # attributes for diagnostics of L2 and L3

        # ont state
        self.__ont_not_connected = False
        self.__ntu1 = False
        self.__state_ok = False
        self.__state_error = ""
        self.__rssi = 0.0
        self.__state_checked = False

        # service profile config
        self.__vlan_config = 0
        self.__service_profile_error = False

        # log
        self.__last_state_error = ""
        self.__ont_flapping = False

        # ports
        self.__ports_link_up = []
        self.__no_ports_active = False
    

    ##### DATABASE AND USER CARD PART #####
    
    # function to control user's database record checking
    @override
    def _check_user_card(self) -> None:
        try:
            # check and make a note about all unnecessary fields
            for field in Country.UNUSED_NUMBER_FIELDS:
                self._correctly_filled[field] = self.__check_unused_number_fields(field)
            for field in Country.UNUSED_IP_FIELDS:
                self._correctly_filled[field] = self.__check_unused_ip_fields(field)
            
            # check if nnet and nserv fields are strictly correct
            for field in Country.NUMBER_FIELDS:
                self._correctly_filled[field] = self.__check_nserv_nnet(field)
            
            # check ip fields
            for field in Country.IP_FIELDS:
                self._correctly_filled[field] = self._check_ip_fields(field)
            
            # if ip exists, check it
            if self._correctly_filled["ip"] == 1:
                # check for double ip
                self._check_double_ip()

                # error flag if ip is not in country subnets
                if not self.__check_country_ip():
                    self.__ip_out_of_country_subnets = True
                
                # if public ip exists
                elif self._correctly_filled["public_ip"] == 1:
                    # error flag if ip and public ip differ
                    if self._record_data["ip"] != self._record_data["public_ip"]:
                        self._different_ip_public_ip = True
                    # otherwise, ip settings are correct
                    else:
                        self.__ip_correct = True

        except Exception:   # exception while checking record
            print("Exception while working with the database record:")
            traceback.print_exc()
        
        finally:   # always close connection and delete database manager
            del self._db_manager

    # check unused number record fields if empty: port, dhcp
    def __check_unused_number_fields(self, field: str) -> int:
        return 1 if not self._record_data[field] else -1

    # check unused ip record fields if empty: mask, gateway, switch
    def __check_unused_ip_fields(self, field: str) -> int:
        return 1 if not self._record_data[field] else -1

    # check if nserv and nnet match country
    def __check_nserv_nnet(self, field: str) -> int:
        if self._record_data[field] == 0:
            return 0
        elif self._record_data[field] == Country.NSERV_NNET:
            return 1
        return -1

    # check if ip or public_ip are correct
    def __check_country_ip(self) -> bool:
        return any(IPv4Address(self._record_data["ip"]) in subnet for subnet in Country.SUBNETS)
    
    # result of database record diagnostics
    @override
    def _result_user_card(self) -> None:
        # flag to monitor if all diagnostics are ok
        all_correct = True

        # if payment is inactive
        if self._inactive_payment:
            print("Неактивный взнос:", self._record_data["payment"])
            all_correct = False
        
        # print empty fields that should be filled
        if any(value == 0 for value in self._correctly_filled.values()):
            print("Не заполнены поля:", ", ".join(name for key, name in Database.KEY_OUTPUT.items() if self._correctly_filled[key] == 0))
            all_correct = False
        
        # print obviously incorrect fields
        if any(value == -1 for value in self._correctly_filled.values()):
            print("Неверно заполнены поля:", ", ".join(name for key, name in Database.KEY_OUTPUT.items() if self._correctly_filled[key] == -1))
            all_correct = False
        
        # double port and ip
        if self._double_ip:
            print("Дубль айпи:", ", ".join(map(str, self._double_ip)))
            all_correct = False
        
        # ip address errors
        if self.__ip_out_of_country_subnets:
            print("Айпи вне деревенских подсетей")
        elif self._different_ip_public_ip:
            print("Поле Внешний IP не совпадает с IP")
        # if everythin is OK and there was no errors before
        elif all_correct:
            print("OK")
    
    
    ##### L2 AND L3 EQUIPMENT DIAGNOSTICS PART #####

    # function to control diagnosing L2 and L3
    @override
    def _check_L2_L3(self) -> None:
        try:
            # get data for olt diagnostics
            self.__get_olt_eltex()
            
            # create L2 manager with one of two versions, depending on olt ip
            if self.__olt_ip in Country.OLTS_VERSION2:
                self._L2_manager = OLTVersion2(self.__olt_ip, self.__eltex_serial, self.__print_output)
            elif self.__olt_ip in Country.OLTS_VERSION3:
                self._L2_manager = OLTVersion3(self.__olt_ip, self.__eltex_serial, self.__print_output)
            else:
                raise MyException(ExceptionType.UNKNOWN_OLT_IP)
            
            # context manager to switch modes
            with self._L2_manager.terminal_context():
                # state
                self.__check_state()
        
        # user's exception include special text for output
        except MyException as err:
            self._L2_exception = err
        
        # exceptions while working with L2 or L3, show traceback
        except Exception:
            print("Exception while working with equipment:")
            traceback.print_exc()
        
        # always close connection and delete L2 and L3 managers
        finally:
            if self._L2_manager:
                del self._L2_manager
            if self._L3_manager:
                del self._L3_manager

    # get olt and eltex from country alarm for further diagnostics
    def __get_olt_eltex(self) -> None:
        # catch list of matches
        try:
            olt_eltex = CountryAlarmManager.get_user_data_from_alarm(self._usernum)
        # alarm error if exception occured
        except:
            raise MyException(ExceptionType.COUNTRY_ALARM_NOT_AVAILABLE)
        
        match len(olt_eltex):
            # error flag if not found
            case 0:
                raise MyException(ExceptionType.ONT_CONFIG_NOT_FOUND)
            # save olt and eltex if exactly one found
            case 1:
                self.__olt_ip, self.__eltex_serial = olt_eltex[0]
            # error flag if more than one found
            case _:
                raise MyException(ExceptionType.SEVERAL_ONT_CONFIGS)
    
    # check ont state
    def __check_state(self):
        # get data from L2 manager
        res = self._L2_manager.get_state()

        # raise exception is nothing found, further diagnostics cannot be performed
        if res is None:
            raise MyException(ExceptionType.ONT_NOT_FOUND)
        
        # get state info: flag if not connected, state error if there is, rssi if found, flag if ntu1
        self.__ont_not_connected, self.__state_error, self.__rssi, self.__ntu1 = res
        
        # if ont connection status is ok, mark flag
        if not self.__ont_not_connected and not self.__state_error:
            self.__state_ok = True
        
        self.__state_checked = True

    # check mac addresses and get as a set
    @override
    def _check_mac(self) -> None:
        pass
    
    # find actual gateway and create L3 manager
    @override
    def _find_actual_gateway(self) -> None:
        pass
    
    # check if vlan's ip interface on L3 matches user's subnet
    @override
    def _check_vlan_subnet(self) -> None:
        pass
    
    # result of L2 and L3 diagnostics
    @override
    def _result_L2_L3(self) -> None:
        # terminate when any fatal error discovered
        if self._L2_exception:
            print(self._L2_exception)
            return
        
        if self.__ont_not_connected:
            print("ONT не подключён")
        elif self.__state_checked:
            print(f"State OK: {self.__state_ok}\nState not OK: {self.__state_error}\nRSSI: {self.__rssi} dBm\nNTU-1: {self.__ntu1}")

"""
ont_not_connected = False
ntu1 = False
state_ok = False
state_error = ""
rssi = 0.0
vlan_config = 0
service_profile_error = False
last_state_error = ""
ont_flapping = False
ports_link_up = []
no_ports_active = False
mac_addresses = set()



session.sendline(f"show interface ont {eltex_serial} state")
session.expect("#")

temp = session.before.decode("utf-8")
match = re.search(r"(?:(?P<not_connected>ONT is not connected)|(Equipment ID:\s+(?P<model>[A-Z0-9-]+).*State:\s+(?P<state>[A-Z]+).*RSSI:\s+(?P<rssi>-\d+\.\d+)))", temp, re.DOTALL)
print(match.groupdict())

if match.group("not_connected"):
    ont_not_connected = True
    print("ONT is not connected")
else:
    ntu1 = match.group("model") == "NTU-1"
    if match.group("state") == "OK":
        state_ok = True
    else:
        state_error = match.group("state")
    rssi = float(match.group("rssi"))
    print(f"NTU-1: {ntu1}\nState not OK: {state_error}\nRSSI: {rssi} dBm")



session.sendline(f"show interface ont {eltex_serial} configuration")
session.expect("#")

temp = session.before.decode("utf-8")
match = re.search(r"Service \[0\]:\s+(?:\[T\])?\s+Profile cross connect:\s+(?P<service>\S+)", temp, re.DOTALL)
print(match.groupdict())

if ntu1:
    match_vlan = re.fullmatch(r"NTU1_(?P<vlan>\d{4})", match.group("service"))
else:
    match_vlan = re.fullmatch(r"(?P<vlan>\d{4})", match.group("service"))

if match_vlan:
    vlan_config = int(match_vlan.group("vlan"))
    print(f"VLAN config: {vlan_config}")
else:
    service_profile_error = True
    print("Неверный конфиг service profile")



session.sendline(f"show interface ont {eltex_serial} connections")
session.expect("#")

temp = session.before.decode("utf-8")
match = re.search(r".*Last state :\s+(?P<last_state>[A-Za-z]+[ -]?[A-Za-z]+)", temp, re.DOTALL)
print(match.groupdict())

if not state_ok or match.group("last_state") != "Working":
    last_state_error = match.group("last_state")

if state_ok:
    matches = re.findall(r"LinkUp :\s+(\d{4}-\d{2}-\d+)\s+(\d{2}:\d{2}:\d{2})", temp)
    match_datetimes = [datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S") for date, time in matches]

    if len(match_datetimes) >= 4 and int((match_datetimes[-1] - match_datetimes[-4]).total_seconds() // 60) <= 10:
        ont_flapping = True

print(f"Last state error: {last_state_error}\nLink flapping: {ont_flapping}")



if state_ok:
    session.sendline(f"show interface ont {eltex_serial} ports")
    session.expect(r"(?<!#)#(?!#)")

    temp = session.before.decode("utf-8")
    ports_count = 1 if ntu1 else 4
    match = re.search(fr"UNI ##(?P<port>(?:\s+\d){{{ports_count}}})\s+Link:(?P<link>(?:\s+\S+){{{ports_count}}})\s+Speed:(?P<speed>(?:\s+\S+){{{ports_count}}})\s+Duplex:(?P<duplex>(?:\s+\S+){{{ports_count}}})", temp, re.DOTALL)
    
    for port, link, speed, duplex in zip(*[group.split() for group in match.group("port", "link", "speed", "duplex")]):
        if link == "up":
            ports_link_up.append({"port": int(port), "speed": speed.replace("1G", "1000M"), "duplex": duplex})
    
    if not ports_link_up:
        no_ports_active = True
        print("Нет активных портов")
    else:
        print("Порты:", ", ".join([f"{i["port"]} - {i["speed"]}/{i["duplex"]}" for i in ports_link_up]))



    session.sendline(f"show mac interface ont {eltex_serial}")
    session.expect(r"(?<!#)#(?!#)")

    temp = session.before.decode("utf-8")
    for match in re.finditer(r"(\d+)\s+(?P<mac>(?:[A-Z\d]{2}:){5}[A-Z\d]{2})", temp):
        mac_addresses.add(match.group("mac").replace(":", "-"))
    
    print("Маки:", mac_addresses)
"""