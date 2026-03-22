#!/usr/bin/python3
import traceback
from typing import Any, override
from ipaddress import IPv4Address
import gc
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
    __ip_correct: bool
    __ip_out_of_country_subnets: bool
    __olt_ip: str
    __eltex_serial: str

    def __init__(self, usernum: int, db_manager: DatabaseManager, record_data: dict[str, Any], inactive_payment: bool, print_output: bool = False) -> None:
        # init with base constructor
        super().__init__(usernum, db_manager, record_data, inactive_payment, print_output)

        # L2 and L3 managers
        self._L2_manager = None
        self._L3_manager = None


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

        # ont freezing error
        self.__ont_freezing = False

        # ont state
        self.__ont_not_connected = False
        self.__ntu1 = False
        self.__state_ok = False
        self.__state_error = ""
        self.__rssi: float | None = None

        # service profile config
        self.__configured_vlan = 0
        self.__service_profile_error = False

        # log
        self.__log_history_not_found = False
        self.__last_state_error = ""
        self.__ont_flapping = False

        # ports
        self.__ports_link_up = []
        self.__no_ports_active = False

        # acs-profile
        self.__acs_profile_not_found = False
        self.__no_base_profile = False
        self.__bridge_profile = False
        self.__wrong_acs_profile_settings = False
        self.__acs_profile_ok = False

        # acs-ont
        self.__acs_ont_not_found = False
        self.__wrong_acs_ont_settings = False
        self.__acs_ont_ok = False

        # acs overall
        self.__acs_ok = False
    

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
                self._L2_manager = OLTVersion2(self.__olt_ip, self.__eltex_serial, self._print_output)
            elif self.__olt_ip in Country.OLTS_VERSION3:
                self._L2_manager = OLTVersion3(self.__olt_ip, self.__eltex_serial, self._print_output)
            else:
                raise MyException(ExceptionType.UNKNOWN_OLT_IP)
            
            # context manager to switch modes
            with self._L2_manager.terminal_context():
                # state
                self.__check_state()

                # config if record's ip is correct
                if self.__ip_correct:
                    self.__check_config()

                # log
                self.__check_log()

                # only if state ok
                if self.__state_ok:
                    # ports
                    self.__check_ports()

                    # base method is used to check mac addresses
                    self._check_mac()
            
            # if ip is not correct, quit with special exceptions
            if not self.__ip_correct:
                raise MyException(ExceptionType.CANNOT_CHECK_ACS_MODE)
            
            # if it's ntu1, skip acs mode checking
            if not self.__ntu1:
                # in acs mode
                with self._L2_manager.acs_context():
                    # in acs-profile mode
                    with self._L2_manager.acs_profile_context():
                        # acs profile settings
                        self.__check_acs_profile()
                    
                    # in acs-ont mode
                    with self._L2_manager.acs_ont_context():
                        # acs ont settings
                        self.__check_acs_ont()
                    
                    # mark flag if the whole olt config is ok
                    if self.__acs_profile_ok and self.__acs_ont_ok:
                        self.__acs_ok = True
            
            # create L3 manager
            self._find_actual_gateway()

            # check ip interface
            self._check_vlan_subnet()

            # check arpentry
            self._check_arpentry_by_ip()
        
        # user's exception include special text for output
        except MyException as err:
            # if ont freezes, mark error flag
            if err.is_ont_freezes_error():
                self.__ont_freezing = True
            # when acs mode cannot be checked, just print message
            elif err.is_cannot_check_acs_mode_error():
                print(err)
            # mark flag if acs-profile/ont not found
            elif err.is_acs_profile_mode_error():
                self.__acs_profile_not_found = True
            elif err.is_acs_ont_mode_error():
                self.__acs_ont_not_found = True
            # save if another, fatal exception
            else:
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
    
    # check ont configuration
    def __check_config(self):
        # check service profile config and get vlan id and ntu-1 flag that helps when it isn't connected
        vlan_id, ntu1 = self._L2_manager.get_service_profile_config(self.__ont_not_connected)

        # error flag if not found
        if vlan_id is None:
            self.__service_profile_error = True
        
        # correct flag if ok, save configured vlan id
        else:
            self.__configured_vlan = vlan_id
            self._vlan_ok = True

            # mark ntu-1 flag if service profile for ntu-1 found when it isn't connected
            if ntu1:
                self.__ntu1 = True
    
    # check log, ont last state and flapping
    def __check_log(self):
        # get data from olt manager
        res = self._L2_manager.get_log(self.__state_ok)

        # error flag if no log found
        if res is None:
            self.__log_history_not_found = True
        
        # if string was returned, save last state error
        elif isinstance(res, str):
            self.__last_state_error = res
        
        # if integer, it's flapping count, mark flag if there's too many flapping
        elif res >= Country.MIN_COUNT_FLAPPING:
            self.__ont_flapping = True

    # check ont active ports
    def __check_ports(self):
        # get info
        self.__ports_link_up = self._L2_manager.get_ports()

        # mark flag if there's no active ports
        if not self.__ports_link_up:
            self.__no_ports_active = True
    
    # check acs profile settings
    def __check_acs_profile(self):
        # get base profile type
        res = self._L2_manager.get_acs_profile_config()
        
        # error flag and return if no base profile found
        if res is None:
            self.__no_base_profile = True
            return
        # mark flag if it's bridge profile, otherwise it's default
        elif res == "bridge":
            self.__bridge_profile = True
        
        # get vlan and ip settings
        vlan, ip, mask, gateway = self._L2_manager.get_acs_profile_property()

        # check profile settings: vlan should be defined in bridge profile, vlan and ip settings in default profile
        # vlan can be configured in service profile, otherwise check defined vlan in acs profile
        if ((vlan == self.__configured_vlan or not self.__configured_vlan and vlan in Country.VLAN_GATEWAY) and 
                (self.__bridge_profile and ip is None and mask is None and gateway is None or
                 not self.__bridge_profile and ip == self._record_data["ip"] and mask == Country.MASK and gateway == Country.VLAN_GATEWAY[self.__configured_vlan])):
            self.__acs_profile_ok = True
        # or set error flag
        else:
            self.__wrong_acs_profile_settings = True
    
    # check acs ont settings
    def __check_acs_ont(self):
        # if profile it set correctly for this ont
        if self._L2_manager.get_acs_ont():
            self.__acs_ont_ok = True
        # if not
        else:
            self.__wrong_acs_ont_settings = True

    # create L3 manager, gateway ip is defined
    @override
    def _find_actual_gateway(self) -> None:
        self._L3_manager = L3Switch(Country.ACTUAL_GATEWAY, self._record_data["ip"], self._print_output)
    
    # check if vlan's ip interface on L3 matches user's subnet
    @override
    def _check_vlan_subnet(self) -> None:
        # can't diagnose if don't have exact configured vlan in service profile
        if not self.__configured_vlan:
            return
        
        # base method checks ip interface with by vlan (id, name and ipif name are the same) and compare with subnet
        super()._check_user_subnet_matches_ip_interface(self.__configured_vlan, self.__configured_vlan, self.__configured_vlan,
                                                        Country.VLAN_GATEWAY[self.__configured_vlan], Country.MASK_LENGTH)
    
    # result of L2 and L3 diagnostics
    @override
    def _result_L2_L3(self) -> None:
        # terminate when any fatal error discovered
        if self._L2_exception:
            print(self._L2_exception)
            return
        
        # specialized terminal model/mode: ntu1, bridge
        if self.__ntu1:
            print("Терминал NTU-1")
        elif self.__bridge_profile:
            print("Терминал в режиме моста")
        
        # state: not connected, error, ok, rssi
        if self.__ont_not_connected:
            print("ONT не подключён")
        elif self.__state_error or self.__state_ok:
            if self.__state_error:
                print("Ошибка состояния:", self.__state_error)
            else:
                print(f"State OK")
            
            # rssi: not available, dbm, high
            rssi_string = "RSSI: "
            if self.__rssi is None:
                rssi_string += "N/A"
            else:
                rssi_string += f"{self.__rssi} dBm"
                if self.__rssi <= Country.HIGH_RSSI:
                    rssi_string += " (высокий)"
            print(rssi_string)
        
        # log: not found, last state, flapping
        if self.__log_history_not_found:
            print("История соединений не найдена")
        elif self.__last_state_error:
            print("Последнее состояние:", self.__last_state_error)
        elif self.__ont_flapping:
            print("Соединение с ONT скачет")
        
        # mac address: no mac, many macs, ok
        if self._no_mac:
            print("Не отображается мак")
        elif self._many_macs:
            print("Маков отображается:", self._many_macs)
        elif self._mac_ok:
            print("Мак OK")
        
        # ports: no active, info about active
        if self.__no_ports_active:
            print("Нет активных портов")
        elif self.__ports_link_up:
            print("Порты:", ", ".join([f"{p["port"]} - {p["speed"]}/{p["duplex"]}" for p in self.__ports_link_up]))
        
        # after main diagnostics output, print message if ont freezes
        if self.__ont_freezing:
            print("ONT зависает")
        
        # service profile config: error, ok
        if self.__service_profile_error:
            print("Неверно настроен влан в config service profile")
        elif self._vlan_ok:
            print("Влан OK")
        
        # acs-profile: mode not found, no base profile, wrong
        if self.__acs_profile_not_found:
            print("Не найден acs-profile")
        elif self.__no_base_profile:
            print("Не назначен базовый профиль в acs-profile")
        elif self.__wrong_acs_profile_settings:
            print("Неверный конфиг acs-profile")
        
        # acs-ont: mode not found, wrong
        if self.__acs_ont_not_found:
            print("Не найден acs-ont")
        elif self.__wrong_acs_ont_settings:
            print("Не настроен верный профиль в acs-ont")
        
        # acs overall: ok
        if self.__acs_ok:
            print("Настройки acs OK")
        
        # arp and mac on L3
        self._result_arp_check()
        
        # ip interface on L3: if not found or subnet for vlan is wrong
        if self._ip_interface_not_found:
            print("Не найден интерфейс для назначенного влана")
        elif self._ip_interface_wrong_subnet:
            print("Подсеть интерфейса для назначенного влана не соответствует подсети айпи из карточки")
