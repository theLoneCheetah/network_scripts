#!/usr/bin/python3
import asyncio
import struct
from typing import override, Any, Callable
from collections import defaultdict
from pprint import pprint
from copy import deepcopy
from datetime import datetime
from time import perf_counter
from pysnmp.hlapi.v3arch.asyncio import *
# local modules
from snmp_client import SNMPClient, RequestData, ResponseData
from const import SNMPRequestType, SwitchConfigSection, SNMP
from snmp_exceptions import *

class L2SwitchClient(SNMPClient):
    _switch_oids_config: dict[str, Any]
    _ports_count: int
    _combo_ports: set[int]
    _fiber_ports: set[int]
    _gigabit_ethernet_ports: set[int]
    _need_to_order_cable_diagnostic_pairs: bool
    _combo_ports_locks: dict[int, asyncio.Lock]
    _combo_ports_are_fiber: dict[int, bool | None]
    
    def __init__(self, ipaddress: str) -> None:
        super().__init__(ipaddress)
    
    @override
    def _post_init(self) -> None:
        # temporary model config
        switch_general_config = self._config["models"][self._model]

        # permanent model oids config
        self._switch_oids_config = switch_general_config["oids"]

        # ports count, combo and fiber ports sets
        self._ports_count = switch_general_config["ports_count"]
        self._combo_ports = switch_general_config["combo_ports"]
        self._fiber_ports = switch_general_config["fiber_ports"]

        # set of gigabit ports based on first gigabit port and ports count
        self._gigabit_ethernet_ports = set(range(switch_general_config["first_gigabit_port"], self._ports_count + 1))

        # pairs should be or shouldn't be ordered for any port based on switch model
        self._need_to_order_cable_diagnostic_pairs = not switch_general_config["are_cable_diagnostic_pairs_ordered"]

        # locks for checking all combo ports
        self._combo_ports_locks = {port: asyncio.Lock() for port in self._combo_ports}
        self._combo_ports_are_fiber = {port: None for port in self._combo_ports}
    
    # check that ethernet port is gigabit
    def _is_gigabit_ethernet_port(self, port: int) -> bool:
        return port in self._gigabit_ethernet_ports
    
    # get pairs count for cable diagnostic using gigabit ethernet port check
    def _get_cable_diagnostic_pairs_count(self, port: int) -> int:
        return 4 if self._is_gigabit_ethernet_port(port) else 2
    
    # check that port is fiber
    def _is_fiber_port(self, port: int) -> bool:
        return port in self._fiber_ports
    
    # check that port is combo on the switch
    def _is_combo_port(self, port: int) -> bool:
        return port in self._combo_ports
    
    # check that in a port is used the fiber port
    def _is_combo_port_fiber(self, port: int) -> bool:
        # if it's not fiber port, return false, port doesn't need to be identified
        if port not in self._combo_ports_are_fiber:
            return False
        
        # otherwise return its status in the dictionary
        return self._combo_ports_are_fiber[port]
    
    # set combo ports status, is fiber port used or not
    def _set_combo_port_is_fiber(self, port: int, is_fiber: bool) -> None:
        # if port number is wrong, raise error
        if port not in self._combo_ports_are_fiber:
            raise ValueError
        
        # otherwise, set the value
        self._combo_ports_are_fiber[port] = is_fiber

    ### MIB MODULES ###

    # get available mibs by private switch oid
    @override
    async def scan_available_mibs(self) -> ResponseData:
        results = defaultdict(dict)
        
        # basically, mibs are identified by indices, so need to collect dictionary by them
        for param in ("description", "version", "mib_type"):
            for oid, desciption in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.PRIVATE_MIBS], [param]):
                results[SNMPClient._parse_last_index(oid)[1]][param] = desciption
        
        # index: {description, version, mib_type} -> description: {version, mib_type} in sorted by mib name order
        return {
            value["description"]: {"version": value["version"], "mib_type": value["mib_type"]}
            for value in sorted(results.values(), key=lambda x: x["description"])
        }
    
    ### SWITCH MANAGEMENT AND INFO ###

    # get any data associated with switch by param list
    async def _get_switch_data(self, include_params: list[str], prefix: str | None = None) -> ResponseData:
        # add optional prefix
        if prefix is not None:
            include_params = [f"{prefix}{param}" for param in include_params]

        # get the results
        results = await self._get(self._switch_oids_config[SwitchConfigSection.SWITCH], include_params)
        
        # return in standard form {request_name: data}, excluding optional prefix
        return {key.removeprefix(prefix): value for key, value in results.items()}
    
    # perform reboot/reset operation
    async def perform_system_reboot(self, request: RequestData) -> SNMPResponseCode:
        mode = request["system_reboot_mode"]
        # for reset system, warning should be thrown
        if mode == "reset_config_and_reboot":
            print("Warning: you will lost connection to this device")
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.SWITCH], request)
        # transport error always occurs, needs to be handled
        except SNMPTransportError:
            # pass mode value to handler
            await self._action_after_system_reboot(next(iter(request.values())))
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # perform save config/log operation
    async def perform_save(self, request: RequestData) -> SNMPResponseCode:
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.SWITCH], request)
            # wait until saved
            await self._check_save_status()
        except SNMPTransportError as err:
            # for config saving, transport error occurs and needs to be handled
            if request["save_action"] in {"config_id1", "config_id2", "all"}:
                await self._check_save_status()
            else:
                return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # function to wait until save action completed
    async def _check_save_status(self) -> None:
        # process status param
        param = "save_status"
        includes_params = [param]

        # while not completed, wait
        status = await self._get(self._switch_oids_config[SwitchConfigSection.SWITCH], includes_params)
        while status[param] not in {"other", "completed"}:
            status = await self._get(self._switch_oids_config[SwitchConfigSection.SWITCH], includes_params)

    # get switch network and vlan configuration
    async def get_network_parameters(self) -> ResponseData:
        include_params = ["ip", "mask", "default_gateway", "management_vlan_id"]
        return await self._get_switch_data(include_params)
    
    # set switch network and vlan
    async def set_network_parameters(self, request: RequestData) -> SNMPResponseCode:
        # warning should be thrown
        print("Warning: this may disrupt connection to this device")
        transport_error = False
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.SWITCH], request)
        # ignore transport error and mark error flag, it may not occur sometimes
        except SNMPTransportError:
            transport_error = True
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        
        # for ip change, handle transport troubles
        if "ip" in request:
            await self._action_after_ip_address_change(request["ip"])
        # for other parameters change, there is no handler now
        elif transport_error:
            return SNMPResponseCode.TRANSPORT_ERROR
        
        return SNMPResponseCode.SUCCESS

    # get switch main mac address
    async def get_mac_address(self) -> ResponseData:
        return await self._get_switch_data(["mac_address"])
    
    # get switch ports number
    async def get_ports_number(self) -> ResponseData:
        return await self._get_switch_data(["ports_number"])

    # get switch current time in datetime format
    async def get_current_time(self) -> ResponseData:
        param = "current_time"
        result = await self._get_switch_data([param])
        result[param] = datetime(*result[param])
        return result
    
    # set switch current time
    async def set_current_time(self, request: RequestData) -> SNMPResponseCode:
        param = "current_time"
        set_value: datetime = request[param]
        # pattern includes 7 fragments, last are ms
        request[param] = set_value.timetuple()[:6] + (set_value.microsecond // 100000,)
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.SWITCH], request)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            elif err.status == "undoFailed":
                # forbidden error is usually caused when sntp is enabled
                return SNMPResponseCode.FORBIDDEN
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    # get switch cpu utilization
    async def get_cpu_utilization(self) -> ResponseData:
        # prefix and params
        base_prefix = "cpu_utilization_"
        include_params = ["5sec", "1min", "5min"]
        results = await self._get_switch_data(include_params, base_prefix)

        # return without prefix
        return {key.removeprefix(base_prefix): value for key, value in results.items()}

    # get switch dynamic ram utilization
    async def get_dram_utilization(self) -> ResponseData:
        # prefix and params
        base_prefix = "dram_"
        include_params = ["total", "used", "utilization"]
        results = await self._get_switch_data(include_params, base_prefix)

        # return without prefix
        return {key.removeprefix(base_prefix): value for key, value in results.items()}
    
    ### TRUSTED HOST ###

    # get trusted hosts supported by switch
    async def get_trusted_hosts(self) -> ResponseData:
        results = defaultdict(dict)

        # for each of ordered host indices, there should be ip and mask
        for oid, ip in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.TRUSTED_HOST], ["ip"]):
            host_index = SNMPClient._parse_last_index(oid)[1]
            # consider 24-bit mask by default
            results[host_index] = {"ip": ip, "mask": "255.255.255.0"}
        
        for oid, mask in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.TRUSTED_HOST], ["mask"]):
            host_index = SNMPClient._parse_last_index(oid)[1]
            # skip masks without ip
            if host_index in results:
                results[host_index]["mask"] = mask
        
        return results

    # add new trusted host for switch
    async def add_trusted_host(self, request: RequestData) -> SNMPResponseCode:
        # warning should be thrown
        print("Warning: this may disrupt connection to this device")

        # include only ip, mask and entry status
        include_params = {param: request[param] for param in ("ip", "mask")}
        include_params["entry_status"] = "create_and_go"

        # trusted host table is filled without spaces, so find first free index to avoid errors
        host_index = await self._find_first_free_host_index()
        oid_vars = {"host_index": host_index}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.TRUSTED_HOST], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # helper function to find first free trusted host index
    async def _find_first_free_host_index(self) -> int:
        occupied_indices = set()

        # find all indices that are occupied
        for oid, _ in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.TRUSTED_HOST], ["ip"]):
            host_index = SNMPClient._parse_last_index(oid)[1]
            occupied_indices.add(host_index)
        
        # search for first free one
        current = 1
        while current in occupied_indices:
            current += 1
        
        return current
    
    # delect one of trusted hosts
    async def delete_trusted_host(self, request: RequestData) -> SNMPResponseCode:
        # include only entry status to destroy
        param = "entry_status"
        include_params = {param: "destroy"}

        # only variable is host index to address by useful number link
        oid_vars = {"host_index": request["host_index"]}

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.TRUSTED_HOST], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # delete all trusted host entries
    async def delete_all_trusted_host(self) -> SNMPResponseCode:
        # main parameter to delete all
        include_params = {"delete_all": "start"}

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.TRUSTED_HOST], include_params)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### ACL ###

    # public methods for getting acl data
    
    # get all acl rule masks and rules in one general table
    async def get_acl_all(self) -> ResponseData:
        ethernet = await self.get_acl_ethernet()
        packet_content = await self.get_acl_packet_content()

        # sort by profile id
        return dict(sorted({**ethernet, **packet_content}.items()))
    
    # get only those acl data that affects the port
    async def get_acl_for_port(self, port: int) -> ResponseData:
        # need to get the general table
        acl_table = await self.get_acl_all()
        result = {}

        # go through all profile id configs
        for profile_id, profile_id_config in acl_table.items():
            rule_management: dict[int, dict[str, Any]] = profile_id_config["rule_management"]

            # check all access ids' entries in the config
            for access_id, access_id_config in rule_management.items():
                # check if rule works for this port
                if port in rule_management[access_id]["ports"]:
                    # for new profile id, add new structure with type and mask
                    if profile_id not in result:
                        result[profile_id] = {
                            "type": profile_id_config["type"],
                            "mask_management": profile_id_config["mask_management"],
                            "rule_management": {}
                        }
                    # add access id rule
                    result[profile_id]["rule_management"][access_id] = access_id_config
        
        return result
    
    # get acl ethernet mask&rule config
    async def get_acl_ethernet(self) -> ResponseData:
        mask = await self._get_acl_ethernet_mask()
        rule = await self._get_acl_ethernet_rule()
        
        return await self._merge_acl_mask_and_rule(mask, rule)
    
    # get acl packet content mask&rule config
    async def get_acl_packet_content(self) -> ResponseData:
        mask = await self._get_acl_packet_content_mask()
        rule = await self._get_acl_packet_content_rule()
        
        return await self._merge_acl_mask_and_rule(mask, rule)

    # helper function to merge mask and rule into one acl table
    async def _merge_acl_mask_and_rule(self, mask: dict[int, dict[str, Any]], rule: dict[int, dict[str, Any]]) -> ResponseData:
        # for each profile id, update config using access id data (acl type is the same)
        for profile_id, profile_id_config in mask.items():
            if profile_id in rule:
                profile_id_config.update(rule[profile_id])
        
        return mask

    # masks getting

    # common function to get and parse acl masks configuration
    async def _get_acl_mask(
                self,
                acl_type: str,   # ethernet or packet content
                params_to_check: list[str],   # filter parameters
                check_profile_id: Callable[[dict[str, str]], dict[str, Any]]   # inner function to check profile id entries
            ) -> ResponseData:
        # add prefix to params
        base_prefix = f"{acl_type}_mask_"
        params_to_check = [f"{base_prefix}{param}" for param in params_to_check]
        pre_results = defaultdict(dict)
        
        # get the parameters as they are, form defaultdict as {profile_id: {param: value}}
        for param in params_to_check:
            for oid, value in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.ACL], [param]):
                # oid's end is the profile id index
                profile_id = SNMPClient._parse_last_index(oid)[1]
                pre_results[profile_id][param] = value
        
        # as mask data will be updated and refilled, another dict needed
        results = {}

        # for each found profile id, check its data
        for profile_id, profile_id_config in pre_results.items():
            temp_profile_id_config = {}

            for param in params_to_check:
                # if any param was not found, skip profile
                if param not in profile_id_config:
                    break
                
                # write parameter without prefix
                temp_profile_id_config[param.removeprefix(base_prefix)] = profile_id_config[param]
            
            else:
                # if all the parameters were found, remember profile id with acl type
                results[profile_id] = {
                    "type": acl_type,
                    # mask data are refilled with special function with custom fields
                    "mask_management": check_profile_id(temp_profile_id_config)
                }
        
        return results

    # get the configuration of ethernet profile id's masks
    async def _get_acl_ethernet_mask(self) -> ResponseData:
        # function to check and refill data in profile id mask, adding custom field
        def check_profile_id(profile_id_config: dict[str, str]) -> dict[str, Any]:
            # for zero/any source/destination mac masks, leave them empty
            if profile_id_config["source_mac_mask"] == SNMP.ZERO_MAC_ADDRESS:
                profile_id_config["source_mac_mask"] = ""
            if profile_id_config["destination_mac_mask"] == SNMP.ZERO_MAC_ADDRESS:
                profile_id_config["destination_mac_mask"] = ""
            
            # ethernet rule should check any frame, so the mask falsely check mac address with zero mask
            source_mac_false_check_state = True \
                if profile_id_config["mac_mask_state"] == "source_mac" and profile_id_config["source_mac_mask"] == "" \
                else False

            return {
                **{key: profile_id_config[key] for key in filter_params},
                # custom variable after filter parameters
                "source_mac_false_check_state": source_mac_false_check_state,
                "owner": profile_id_config["owner"]
            }

        acl_type = "ethernet"
        # filter params are specified separately for useful key order
        filter_params = ["use_vlan", "mac_mask_state", "source_mac_mask", "destination_mac_mask", "use_802_1p", "use_ethernet_type"]
        params_to_check = [*filter_params, "owner"]

        # common function does all the work
        return await self._get_acl_mask(acl_type, params_to_check, check_profile_id)

    # get the configuration of packet content profile id's masks
    async def _get_acl_packet_content_mask(self) -> ResponseData:
        # function to check and refill data in profile id mask, adding custom fields
        def check_profile_id(profile_id_config: dict[str, str]) -> dict[str, Any]:
            # combine masks into a general one
            general_mask = "0x" + "".join(profile_id_config[mask][2:] for mask in masks)
            # based on bytes that are fully inspected, decide which of ipv4/arp fields are checked
            fully_inspected_bytes = L2SwitchClient._parse_acl_packet_content_fully_inspected_bytes(general_mask[2:])
            ipv4_arp_check_state = L2SwitchClient._discover_acl_packet_content_ipv4_arp_check_state(fully_inspected_bytes)

            return {
                # offsets masks keeps their shape
                "offset_masks": {
                    mask: profile_id_config[mask]
                    for mask in masks
                },
                # custom fields
                "general_mask": general_mask,
                "fully_inspected_bytes": fully_inspected_bytes,
                "ipv4_arp_check_state": ipv4_arp_check_state,
                "owner": profile_id_config["owner"]
            }
        
        acl_type = "packet_content"
        # masks as filter params separately for iteration
        masks = ["offset_0_15", "offset_16_31", "offset_32_47", "offset_48_63", "offset_64_79"]
        params_to_check = [*masks, "owner"]

        # common function does all the work
        return await self._get_acl_mask(acl_type, params_to_check, check_profile_id)

    # rules getting

    # common function to get and parse acl rule configuration
    async def _get_acl_rule(
                self,
                acl_type: str,   # ethernet or packet content
                params_to_check: list[str],   # filter parameters
                convert_value: Callable[[dict[str, Any], str], Any],   # inner function to convert specified values
                transform_access_id_config: Callable[[dict[str, Any]], dict[str, Any]]   # inner function to check access id entries
            ) -> ResponseData:
        # add prefix to params
        base_prefix = f"{acl_type}_rule_"
        params_to_check = [f"{base_prefix}{param}" for param in params_to_check]

        # form defaultdict as {profile_id: {access_id: {param: value}}}
        pre_results = defaultdict(lambda: defaultdict(dict))
        
        # get the parameters as they are
        for param in params_to_check:
            for oid, value in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.ACL], [param]):
                # oid is {base}.{profile_id}.{access_id}, cut ids
                cut_oid, access_id = SNMPClient._parse_last_index(oid)
                profile_id = SNMPClient._parse_last_index(cut_oid)[1]
                pre_results[profile_id][access_id][param] = value
        
        # as rule data will be updated and refilled, another dict needed
        results = {}
        
        # for each found profile id, check its data
        for profile_id, profile_id_config in pre_results.items():
            # profile id should exist even if access ids are skipped, because it shoud have at least a mask
            results[profile_id] = {
                "type": acl_type,
                "rule_management": defaultdict(dict)
            }
            rule_management = results[profile_id]["rule_management"]

            for access_id, access_id_config in profile_id_config.items():
                temp_access_id_config = {}

                for param in params_to_check:
                    # if any param was not found, skip rule
                    if param not in access_id_config:
                        break
                    
                    # get the value and remove params's prefix
                    value = access_id_config[param]
                    param = param.removeprefix(base_prefix)

                    # write value after coversion and hiding zero fields
                    temp_access_id_config[param] = convert_value(param, value)
                else:
                    # if all the parameters were found, remember transformed access id
                    rule_management[access_id] = transform_access_id_config(temp_access_id_config)
        
        return results
    
    # get the configuration of ethernet access id's rules
    async def _get_acl_ethernet_rule(self) -> ResponseData:
        # function to check and transform rule params' values
        def convert_value(param: str, value: Any) -> Any:
            match param:
                # when vlan name is not stated, the value is 64-byte zero string, miss it
                case "vlan_name":
                    if value == SNMP.ZERO_VLAN_NAME:
                        value = ""
                # miss zero/any mac address values
                case "source_mac" | "destination_mac":
                    if value == SNMP.ZERO_MAC_ADDRESS:
                        value = ""
                # 802.1p default -1 becomes "" for unified form
                case "check_802_1p":
                    if value == -1:
                        value = ""
                # miss zero/any ethernet type value
                case "ethernet_type":
                    if value == SNMP.ZERO_ETHERNET_TYPE:
                        value = ""
                # for ports, get the portlist
                case "ports":
                    value = L2SwitchClient._parse_assigned_ports_from_hex(value, self._ports_count)

            return value
        
        # function to calculate custom field and transform access id
        def transform_access_id_config(access_id_config: dict[str, Any]) -> dict[str, Any]:
            # access id rule checks every frame if all filter params have default values
            deny_any_frame = all(access_id_config[key] == "" for key in filter_params)
            
            # return dict with custom field inside
            return {
                **{key: access_id_config[key] for key in filter_params},
                "deny_any_frame": deny_any_frame,
                **{key: access_id_config[key] for key in secondary_params}
            }

        acl_type = "ethernet"
        # filter params separately for custom field
        filter_params = ["vlan_name", "source_mac", "destination_mac", "check_802_1p", "ethernet_type"]
        secondary_params = ["enable_local_priority", "local_priority", "permit", "ports", "owner", "rx_rate"]
        params_to_check = filter_params + secondary_params
        
        # common function does all the work
        return await self._get_acl_rule(acl_type, params_to_check, convert_value, transform_access_id_config)

    # get the configuration of packet content access id's rules
    async def _get_acl_packet_content_rule(self) -> ResponseData:
        # function to check and transform rule params' values
        def convert_value(param: str, value: Any) -> Any:
            match param:
                # for ports, get the portlist
                case "ports":
                    value = L2SwitchClient._parse_assigned_ports_from_hex(value, self._ports_count)
            
            return value
        
        # function to calculate custom fields and transform access id
        def transform_access_id_config(access_id_config: dict[str, Any]) -> dict[str, Any]:
            offset_chunks = {}
            
            # go through all chunks
            for ind in range(1, 6):
                # get index (offset), mask and data
                index, mask, data = [access_id_config.pop(f"offset_{param}_{ind}") for param in ("index", "mask", "data")]

                # keep only those offset chunks that have not default value
                if mask != SNMP.ZERO_OFFSET_CHUNK:
                    # for each chunk, calculate bytes that are fully inspected, mask is prefilled with spaces
                    fully_inspected_bytes = L2SwitchClient._parse_acl_packet_content_fully_inspected_bytes("00" * index + mask[2:])
                    offset_chunks[index] = {
                        "mask": mask,
                        "data": data,
                        "fully_inspected_bytes": fully_inspected_bytes
                    }
            
            # sort offset chunks ascending
            offset_chunks = dict(sorted(offset_chunks.items()))

            # main data and custom fields that are filled when rule has one offset chunk
            mask, data = "", ""
            fully_inspected_bytes = set()
            ipv4_arp_check_state = "none"   # by default, rule doesn't check anything
            source_ip = ""

            # access id rule is considered wrong if any other chunk doesn't have default value
            if len(offset_chunks) == 1:
                main_offset_chunk = next(iter(offset_chunks.values()))
                # get data from the main and only offset chunk
                mask, data, fully_inspected_bytes = (
                    main_offset_chunk[key] for key in ("mask", "data", "fully_inspected_bytes")
                )
                
                # decide which of ipv4/arp fields are checked
                ipv4_arp_check_state = L2SwitchClient._discover_acl_packet_content_ipv4_arp_check_state(fully_inspected_bytes)
                # source ip will be filled only if access id rule checks ipv4/arp source ip with real value
                if ipv4_arp_check_state in {"ipv4", "arp"} and data != SNMP.ZERO_OFFSET_CHUNK:
                    source_ip = L2SwitchClient._parse_acl_chunk_to_ip(data)
            
            # form resulting dict, starting with offset chunks and custom fields
            return {
                "offsets": offset_chunks,
                "main_mask": mask,
                "main_data": data,
                "fully_inspected_bytes": fully_inspected_bytes,
                "ipv4_arp_check_state": ipv4_arp_check_state,
                "source_ip": source_ip,
                **{key: access_id_config[key] for key in secondary_params}
            }

        acl_type = "packet_content"
        # filter params (3 fields for each of 5 blocks) separately
        filter_params = [
            f"offset_{param}_{ind}"
            for ind in range(1, 6)
            for param in ("index", "mask", "data")
        ]
        secondary_params = ["enable_local_priority", "local_priority", "permit", "ports", "rx_rate"]
        params_to_check = filter_params + secondary_params
        
        # common function does all the work
        return await self._get_acl_rule(acl_type, params_to_check, convert_value, transform_access_id_config)
    
    # public mask/rule setting methods

    # create new acl ethernet mask
    async def create_acl_ethernet_mask(self, request: RequestData) -> SNMPResponseCode:
        return await self._create_acl_mask("ethernet", request, self._build_acl_ethernet_mask_include_params)

    # create new acl packet content mask
    async def create_acl_packet_content_mask(self, request: RequestData) -> SNMPResponseCode:
        return await self._create_acl_mask("packet_content", request, self._build_acl_packet_content_mask_include_params)
    
    # add new acl ethernet rule
    async def add_acl_ethernet_rule(self, request: RequestData) -> SNMPResponseCode:
        return await self._add_acl_rule("ethernet", request, self._build_acl_ethernet_rule_include_params)
    
    # add new acl packet content rule
    async def add_acl_packet_content_rule(self, request: RequestData) -> SNMPResponseCode:
        return await self._add_acl_rule("packet_content", request, self._build_acl_packet_content_rule_include_params)

    # mask/rule deleting

    # delete ethernet profile id
    async def delete_acl_ethernet_mask(self, request: RequestData) -> SNMPResponseCode:
        return await self._delete_acl_entry("ethernet_mask_", request["profile_id"])
    
    # delete packet content profile id
    async def delete_acl_packet_content_mask(self, request: RequestData) -> SNMPResponseCode:
        return await self._delete_acl_entry("packet_content_mask_", request["profile_id"])
    
    # delete ethernet access id
    async def delete_acl_ethernet_rule(self, request: RequestData) -> SNMPResponseCode:
        return await self._delete_acl_entry("ethernet_rule_", request["profile_id"], request["access_id"])
    
    # delete packet content access id
    async def delete_acl_packet_content_rule(self, request: RequestData) -> SNMPResponseCode:
        return await self._delete_acl_entry("packet_content_rule_", request["profile_id"], request["access_id"])
    
    # common method to delete acl profile or access id
    async def _delete_acl_entry(self, base_prefix: str, profile_id: int, access_id: int = None) -> SNMPResponseCode:
        # if mask doesn't exist, return error
        if await self._get_acl_entry_status(base_prefix, profile_id, access_id) is None:
            return SNMPResponseCode.INVALID_DATA
        
        # destroy value for entry
        param = f"{base_prefix}entry_status"
        include_params = {param: "destroy"}

        # profile id var - always
        oid_vars = {"profile_id": profile_id}
        # access id var - if has it
        if access_id is not None:
            oid_vars["access_id"] = access_id

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.ACL], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "notWritable":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # helper method to check if acl mask or rule exists
    async def _get_acl_entry_status(self, base_prefix: str, profile_id: int, access_id: int = None) -> str:
        # entry status param
        param = f"{base_prefix}entry_status"

        # profile id var - always
        oid_vars = {"profile_id": profile_id}
        # access id var - if has it
        if access_id is not None:
            oid_vars["access_id"] = access_id
        
        # return entry status value
        return (await self._get(self._switch_oids_config[SwitchConfigSection.ACL], [param], oid_vars))[param]
    
    # mask setting

    # common method for creating acl masks
    async def _create_acl_mask(
                self,
                acl_type: str,   # ethernet or packet content
                request: RequestData,   # user's request
                build_include_params: Callable[[RequestData], dict[str, Any]]
            ) -> SNMPResponseCode:
        # form prefix based on acl type
        base_prefix = f"{acl_type}_mask_"

        # if mask with specified profile id already exists, return error
        if await self._get_acl_entry_status(base_prefix, request["profile_id"]) == "active":
            return SNMPResponseCode.INVALID_DATA
        
        # build params dict by specific method
        try:
            include_params = build_include_params(request)
        # if ValueError was raised, request data are invalid, return error
        except ValueError:
            return SNMPResponseCode.INVALID_DATA
        
        # entry status param
        include_params["entry_status"] = "create_and_go"
        # add prefix
        include_params = {f"{base_prefix}{param}": value for param, value in include_params.items()}
        
        # profile id var
        oid_vars = {"profile_id": request["profile_id"]}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.ACL], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "notWritable":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    # build parameters for ethernet mask setting
    def _build_acl_ethernet_mask_include_params(self, request: RequestData) -> dict[str, Any]:
        # if got advanced params
        if advanced_params := request.get("advanced_params"):
            # mac_mask_state oid is necessary for identifying any mac mask
            if "source_mac_mask" in advanced_params:
                if "destination_mac_mask" in advanced_params:
                    mac_mask_state = "destination_source_mac"
                else:
                    mac_mask_state = "source_mac"
            elif "destination_mac_mask" in advanced_params:
                mac_mask_state = "destination_mac"
            # default
            else:
                mac_mask_state = "other"
            
            include_params = {}

            # mac_mask_state before mac masks
            if mac_mask_state != "other":
                include_params["mac_mask_state"] = mac_mask_state
            # other params
            include_params.update(advanced_params)
        
        # custom request by source_mac_false_check_state
        else:
            # only source mac with zero value
            include_params = {
                "mac_mask_state": "source_mac",
                "source_mac_mask": SNMP.ZERO_MAC_ADDRESS
            }
        
        return include_params

    # build parameters for packet content mask setting
    def _build_acl_packet_content_mask_include_params(self, request: RequestData) -> dict[str, Any]:
        # for custom request by ipv4_arp_check_state, create fully_inspected_bytes set
        if ipv4_arp_check_state := request.get("ipv4_arp_check_state"):
            match ipv4_arp_check_state:
                # for both ipv4/arp check, some bytes intersects
                case "both":
                    fully_inspected_bytes = SNMP.SOURCE_IP_BYTES_IN_IPV4 | SNMP.SOURCE_IP_BYTES_IN_ARP
                case "ipv4":
                    fully_inspected_bytes = SNMP.SOURCE_IP_BYTES_IN_IPV4
                case "arp":
                    fully_inspected_bytes = SNMP.SOURCE_IP_BYTES_IN_ARP
                # if state is unknown, raise error
                case _:
                    raise ValueError
        
        # otherwise, some of advanced params was defined
        else:
            advanced_params: dict[str, Any] = request.get("advanced_params")
            # get this parameter
            fully_inspected_bytes = advanced_params.get("fully_inspected_bytes")
            general_mask = advanced_params.get("general_mask")   # if general mask was defined, bytes stage will be skipped
            offset_masks = advanced_params.get("offset_masks")   # if offset masks were defined, bytes and general mask stages will be skipped
        
        # it's easy to create general mask from bytes if there are any
        if fully_inspected_bytes:
            general_mask = "0x" + "".join((
                "ff" if byte in fully_inspected_bytes else "00"
                for byte in range(80)
            ))

        # if there is a general mask, cut it to offset masks
        if general_mask:
            general_mask = general_mask[2:]
            offset_masks = {}

            for i in range(0, len(general_mask) // 2, 16):
                chunk_mask = general_mask[i * 2 : i * 2 + 32]
                # exclude empty offset masks
                if int(chunk_mask, 16) != 0:
                    # hex value is expected with 0x
                    offset_masks[f"offset_{i}_{i + 15}"] = f"0x{chunk_mask}"
        
        # offset_masks = include_params
        return offset_masks
    
    # rule setting

    # common method for adding acl rules
    async def _add_acl_rule(
                self,
                acl_type: str,   # ethernet or packet content
                request: RequestData,   # user's request
                build_include_params: Callable[[RequestData], dict[str, Any]]
            ) -> SNMPResponseCode:
        # form prefix based on acl type
        base_prefix = f"{acl_type}_rule_"

        # if profile id doesn't exist or access id already exists, return error
        if await self._get_acl_entry_status(f"{acl_type}_mask_", request["profile_id"]) is None or \
                await self._get_acl_entry_status(base_prefix, request["profile_id"], request["access_id"]) == "active":
            return SNMPResponseCode.INVALID_DATA
        
        # build params dict by specific method
        try:
            include_params = build_include_params(request)
        # if ValueError was raised, request data are invalid, return error
        except ValueError:
            return SNMPResponseCode.INVALID_DATA
        
        # ports as a hex string, entry status param
        include_params["ports"] = L2SwitchClient._combine_assigned_ports_to_hex(request["ports"])
        include_params["entry_status"] = "create_and_go"
        # add prefix
        include_params = {f"{base_prefix}{param}": value for param, value in include_params.items()}

        # profile id and access id vars
        oid_vars = {"profile_id": request["profile_id"], "access_id": request["access_id"]}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.ACL], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    # build parameters for ethernet rule setting
    def _build_acl_ethernet_rule_include_params(self, request: RequestData) -> dict[str, Any]:
        # if got advanced params
        if advanced_params := request.get("advanced_params"):
            include_params = {}

            # enable_local_priority oid is necessary for local_priority oid and should be before
            if "local_priority" in advanced_params:
                include_params["enable_local_priority"] = "enabled"
            # other params10.136.191.64
            include_params.update(advanced_params)
        
        # custom request by deny_any_frame
        else:
            include_params = {
                "source_mac": SNMP.ZERO_MAC_ADDRESS,   # zero mac, nothing to check as maak is also empty
                "permit": "deny"   # deny any frames
            }

        return include_params

    # build parameters for packet content rule setting
    def _build_acl_packet_content_rule_include_params(self, request: RequestData) -> dict[str, Any]:
        # if got advanced params
        if advanced_params := request.get("advanced_params"):
            offsets: dict[int, str] = advanced_params["offsets"]
            include_params = {}

            # form offset param sorted by bytes index
            for ind, (offset, mask) in enumerate(sorted(list(offsets.items()))):
                include_params[f"offset_index_{ind + 1}"] = offset   # bytes offset
                include_params[f"offset_data_{ind + 1}"] = mask   # chunk mask
            
            # enable_local_priority oid is necessary for local_priority oid
            if "local_priority" in advanced_params:
                include_params["enable_local_priority"] = "enabled"
            # other params
            include_params.update({param: value for param, value in advanced_params.items() if param != "offsets"})
        
        # custom request by protocol and ip address
        else:
            custom_params = request.get("custom_params")

            # get protocol type (ipv4/arp)
            ipv4_arp_check_state = custom_params["ipv4_arp_check_state"]
            if ipv4_arp_check_state not in {"ipv4", "arp"}:   # if protocol type is unknown, raise error
                raise ValueError
            
            # get source ip to filter
            source_ip = custom_params["source_ip"]

            include_params = {
                "offset_index_1": (
                    SNMP.SOURCE_IP_OFFSET_IN_IPV4   # bytes offset according to protocol type
                    if ipv4_arp_check_state == "ipv4"
                    else SNMP.SOURCE_IP_OFFSET_IN_ARP
                ),
                "offset_data_1": L2SwitchClient._convert_ip_to_acl_chunk(source_ip),   # convert ip into hex chunk
                "permit": "permit"   # permit frames with this ip
            }
        
        return include_params

    ### VLAN ###

    # get the whole vlan table in tagged/untagged ports
    async def get_vlan_static_table(self) -> dict[int, dict[str, Any]]:
        results = defaultdict(dict)
        
        # vlan names
        for oid, vlan_name in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.VLAN], ["name"]):
            # vlan id is the last oid index
            vlan_id = SNMPClient._parse_last_index(oid)[1]
            
            # consider default empty sets for tagged/untagged ports
            results[vlan_id] = {"vlan_name": vlan_name, "tagged_ports": set(), "untagged_ports": set()}
        
        # get egress ports, including all tagged and untagged ports
        for oid, octet_string in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.VLAN], ["egress_ports"]):
            vlan_id = SNMPClient._parse_last_index(oid)[1]
            
            # if vlan is known, write ports converted from hex
            if vlan_id in results:
                results[vlan_id]["tagged_ports"] = L2SwitchClient._parse_assigned_ports_from_hex(octet_string, self._ports_count)
        
        # get untagged ports
        for oid, octet_string in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.VLAN], ["untagged_ports"]):
            vlan_id = SNMPClient._parse_last_index(oid)[1]
            # convert ports from hex
            portlist = L2SwitchClient._parse_assigned_ports_from_hex(octet_string, self._ports_count)

            # skip unknown vlans, write untagged ports
            if vlan_id in results:
                results[vlan_id]["untagged_ports"] = portlist
                # for tagged ports that include all, remove those that are untagged to leave only tagged
                results[vlan_id]["tagged_ports"] -= portlist
        
        # {vlan_id: {vlan_name, tagged_ports, untagged_ports}}
        return results
    
    # get vlan configuration for port
    async def get_vlan_on_port(self, port: int) -> ResponseData:
        result = defaultdict(dict)

        # for each vlan in the general table
        for vlan_id, vlan_data in (await self.get_vlan_static_table()).items():
            vlan_name =  vlan_data["vlan_name"]
            # remember if tagged
            if port in vlan_data["tagged_ports"]:
                result["tagged"][vlan_id] = vlan_name
            # remember if untagged
            elif port in vlan_data["untagged_ports"]:
                result["untagged"][vlan_id] = vlan_name

        # {tagged: {vlan_id: vlan_name}, untagged: {vlan_id: vlan_name}}
        return result
    
    # create new vlan
    async def create_vlan(self, request: RequestData) -> SNMPResponseCode:
        vlan_id = request["vlan_id"]
        # if vlan with this vlan id already exists, return error
        if await self._get_vlan_entry_status(vlan_id) == "active":
            return SNMPResponseCode.INVALID_DATA
        
        # params include vlan name and entry status
        include_params = {
            "name": request["vlan_name"],
            "entry_status": "create_and_go"
        }

        # vlan id var
        oid_vars = {"vlan_id": vlan_id}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.VLAN], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "commitFailed":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # delete vlan entry by vlan id
    async def delete_vlan(self, request: RequestData) -> SNMPResponseCode:
        vlan_id = request["vlan_id"]
        # if vlan id doesn't exist, return error
        if await self._get_vlan_entry_status(vlan_id) is None:
            return SNMPResponseCode.INVALID_DATA
        
        # destroy entry param
        param = "entry_status"
        include_params = {param: "destroy"}

        # vlan id var
        oid_vars = {"vlan_id": vlan_id}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.VLAN], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # configure vlan as tagged/untagged for ports
    async def add_vlan_on_ports(self, request: RequestData) -> SNMPResponseCode:
        vlan_id = request["vlan_id"]
        # if vlan id doesn't exist, return error
        if await self._get_vlan_entry_status(vlan_id) is None:
            return SNMPResponseCode.INVALID_DATA

        # get param name according to status, return error if not found
        status = request["status"]
        param = SNMP.PARAM_FOR_VLAN_STATUS.get(status)
        if param is None:
            return SNMPResponseCode.INVALID_DATA
        
        # combine current egress/untagged portlist with new ports
        # tagged + egress -> tagged
        # untagged + egress -> untagged
        # untagged + untagged -> untagged
        portlist = request["portlist"] | await self._get_ports_with_snmp_vlan_status(vlan_id, param)
        # convert portlist to hex string
        include_params = {param: L2SwitchClient._combine_assigned_ports_to_hex(portlist)}

        # vlan id var
        oid_vars = {"vlan_id": vlan_id}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.VLAN], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "commitFailed":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # delete vlan status from ports
    async def delete_vlan_from_ports(self, request: RequestData) -> SNMPResponseCode:
        vlan_id = request["vlan_id"]
        # if vlan id doesn't exist, return error
        if await self._get_vlan_entry_status(vlan_id) is None:
            return SNMPResponseCode.INVALID_DATA

        # status is tagged because zero mask in egress_ports request removes ports from any vlan status
        param = SNMP.PARAM_FOR_VLAN_STATUS.get("tagged")
        
        # substract portlist for deletion from current portlist
        portlist = await self._get_ports_with_snmp_vlan_status(vlan_id, param) - request["portlist"]
        # convert to hex string
        include_params = {param: L2SwitchClient._combine_assigned_ports_to_hex(portlist)}

        # vlan id var
        oid_vars = {"vlan_id": vlan_id}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.VLAN], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    # change vlan name referring to vlan id
    async def rename_vlan(self, request: RequestData) -> SNMPResponseCode:
        """
        WARNING: this way of changing VLAN's name is not stable and disrupts users' connections.
        """
        vlan_id = request["vlan_id"]
        # if vlan id doesn't exist, return error
        if await self._get_vlan_entry_status(vlan_id) is None:
            return SNMPResponseCode.INVALID_DATA
        
        # get vlan config before changes
        old_vlan_data = await self._get_exact_vlan_id_table(vlan_id)

        # delete this vlan or return error
        response = await self.delete_vlan({"vlan_id": vlan_id})
        if response != SNMPResponseCode.SUCCESS:
            return response
        
        # create vlan with new name or return error
        response = await self.create_vlan(request)
        if response != SNMPResponseCode.SUCCESS:
            return response
        
        # add ports back in tagged/untagged
        for status in ("tagged", "untagged"):
            response = await self.add_vlan_on_ports({
                "vlan_id": vlan_id,
                "portlist": old_vlan_data[f"{status}_ports"],
                "status": status
            })
            # return error if occured
            if response != SNMPResponseCode.SUCCESS:
                return response
        
        # return final response status
        return response

    # check that vlan_id entry exists, necessary for delete vlan, add/delete vlan on ports operations
    async def _get_vlan_entry_status(self, vlan_id: int) -> ResponseData:
        # entry status with vlan id var
        param = "entry_status"
        oid_vars = {"vlan_id": vlan_id}

        # return entry status value
        return (await self._get(self._switch_oids_config[SwitchConfigSection.VLAN], [param], oid_vars))[param]
    
    # get ports that are egress or untagged for the vlan id
    async def _get_ports_with_snmp_vlan_status(self, vlan_id: int, param: str) -> set[int]:
        # vlan id var
        oid_vars = {"vlan_id": vlan_id}
        
        # get portlist as hex and return as a set
        result = await self._get(self._switch_oids_config[SwitchConfigSection.VLAN], [param], oid_vars)
        return L2SwitchClient._parse_assigned_ports_from_hex(result[param], self._ports_count)
    
    # get vlan static table for specified vlan id
    async def _get_exact_vlan_id_table(self, vlan_id: int) -> ResponseData:
        # use general vlan table to find specific vlan id config
        return (await self.get_vlan_static_table()).get(vlan_id, {})
    
    ### FDB ###

    # get general fdb table
    async def get_fdb_table(self) -> dict[int, dict[str, dict[str, Any]]]:
        results = defaultdict(dict)

        # get mac addresses' ports
        for oid, port in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.FDB], ["port"]):
            # cut vlan id and mac from oid
            _, vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(oid)
            # default status is dynamic, so if mac's status won't be found it means it's dynamic
            results[vlan_id][mac] = {"port": port, "status": "dynamic"}

        # get statuses
        for oid, status in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.FDB], ["status"]):
            # cut vlan id and mac from oid
            _, vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(oid)

            # if mac's port is unknown, don't count it
            if mac not in results[vlan_id]:
                continue
            
            # learned = dynamic, remember status
            if status not in {"invalid" , "self"}:
                status = "dynamic" if status == "learned" else "static"
            results[vlan_id][mac]["status"] = status

        # {vlan_id: {mac: {port, status}}}
        return results
    
    # get fdb data for port
    async def get_fdb_on_port(self, port: int) -> ResponseData:
        result = defaultdict(dict)

        # go through the general fdb table
        for vlan_id, mac_list in (await self.get_fdb_table()).items():
            for mac, mac_info in mac_list.items():
                # if mac's ports is current port and status is dynamic/static
                if mac_info["port"] == port and mac_info["status"] not in {"invalid" , "self"}:
                    # first key is mac for fast search
                    result[mac][vlan_id] = {"status": mac_info["status"]}
        
        # {mac: {vlan_id: {status}}}
        return result
    
    # clear fdb on port by switching port security on port
    async def clear_fdb_on_port(self, port: int) -> SNMPResponseCode:
        # turn port security on
        result = await self.set_port_security_on_port({"admin_state": "enable"}, port)

        # return error status if occured
        if result != SNMPResponseCode.SUCCESS:
            return result
        
        # turn port security off
        return await self.set_port_security_on_port({"admin_state": "disable"}, port)
    
    # clear general switch fdb table
    async def clear_fdb_all(self) -> SNMPResponseCode:
        # clear all param
        include_params = {"clear_all": "start"}

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.FDB], include_params)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### FLOOD FDB ###

    # get flood fdb table
    async def get_flood_fdb(self) -> ResponseData:
        # get flood fdb state
        results = await self._get(self._switch_oids_config[SwitchConfigSection.FLOOD_FDB], ["state"])
        # if disabled, return
        if results["state"] == "disabled":
            return results
        
        # table for flood fdb mac addresses
        table = defaultdict(dict)
        
        # get mac addresses' statuses
        for oid, status in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.FLOOD_FDB], ["status"]):
            # cut flood fdb index, vlan id and mac from oid
            cut_oid, vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(oid)
            index = SNMPClient._parse_last_index(cut_oid)[1]

            # by default, write flood fdb entry without timestamp
            table[index][mac] = {"vlan_id": vlan_id, "status": status}
        
        # get mac addresses' timestamps
        for oid, timestamp in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.FLOOD_FDB], ["timestamp"]):
            # cut flood fdb index, vlan id and mac from oid
            cut_oid, vlan_id, mac = L2SwitchClient._parse_vlan_id_mac_from_oid_suffix(oid)
            index = SNMPClient._parse_last_index(cut_oid)[1]

            # if index or mac is unknown, don't count entry
            if index in table and mac in table[index]:
                table[index][mac]["timestamp"] = timestamp
        
        # return the whole flood fdb data: {state, {index: {mac: {vlan_id, status, timestamp}}}}
        results["table"] = table
        return results
    
    # set flood fdb state
    async def set_flood_fdb(self, request: RequestData) -> SNMPResponseCode:
        # only flood fdb state param
        include_params = {"state": request["state"]}

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.FLOOD_FDB], include_params)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # clear flood fdb table
    async def clear_flood_fdb(self) -> SNMPResponseCode:
        # clear flood fdb param
        include_params = {"clear": "start"}

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.FLOOD_FDB], include_params)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### IPIF ###

    # get ipif name for system ipif index
    async def _get_ipif_name(self, if_index: int) -> ResponseData:
        # get name using index var
        param = "name"
        oid_vars = {"if_index": if_index}

        # return ipif name
        return (await self._get(self._switch_oids_config[SwitchConfigSection.IPIF], [param], oid_vars))[param]

    ### DHCP RELAY ###

    # get dhcp relay configuration
    async def get_dhcp_relay(self) -> ResponseData:
        # get main params: state, hops, threshold, option82 details
        include_params = [
            "state", "hop_count", "time_threshold",
            "option82_state", "option82_check_state", "option82_policy",
            "option82_remote_id_type", "option82_remote_id"
        ]
        results = await self._get(self._switch_oids_config[SwitchConfigSection.DHCP_RELAY], include_params)

        # two defaultdicts for different relay matches
        results["ipif_servers"] = defaultdict(set)
        # results["vlan_id_servers"] = defaultdict(set)

        # get ipif names for dhcp servers
        for oid, ipif_name in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.DHCP_RELAY], ["ipif_server"]):
            # cut server ip from oid
            server_ip = L2SwitchClient._parse_ip_address_from_oid(oid)[1]
            # add server for ipif name
            results["ipif_servers"][ipif_name].add(server_ip)
        
        # vlan id - servers logic will be implemented for other switch models

        # {main params, ipif_servers: {ipif_name: {servers}}}
        return results
    
    # set dhcp relay global management
    async def set_dhcp_relay(self, request: RequestData) -> SNMPResponseCode:
        # all parameters and values are in request
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.DHCP_RELAY], request)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # add dhcp server entries for ipif
    async def add_dhcp_server_for_ipif(self, request: RequestData) -> SNMPResponseCode:
        # use common management method to create new entry
        return await self._manage_dhcp_server_for_ipif(request, "create_and_go")
    
    # delete dhcp server entries for ipif
    async def delete_dhcp_server_for_ipif(self, request: RequestData) -> SNMPResponseCode:
        # use common management method to delete entry
        return await self._manage_dhcp_server_for_ipif(request, "destroy")

    # common method to add/delete dhcp server for ipif
    async def _manage_dhcp_server_for_ipif(self, request: RequestData, mode: str) -> SNMPResponseCode:
        # entry status with specified mode value
        param = "ipif_server_entry_status"
        include_params = {param: mode}

        # ipif name and dhcp server vars from request
        oid_vars = {
            "ipif_name": L2SwitchClient._convert_name_into_oid(request["ipif_name"]),
            "dhcp_server": request["server"]
        }
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.DHCP_RELAY], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### ARP ###

    # get general switch arp table
    async def get_arp_table(self) -> ResponseData:
        results = defaultdict(dict)
        ipif_names = {}   # stores ipif names for their system indices

        # get mac addresses for ip
        for oid, mac in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.ARP], ["mac_address"]):
            # cut ip address and ipif index from oid
            cut_oid, ip = L2SwitchClient._parse_ip_address_from_oid(oid)
            if_index = SNMPClient._parse_last_index(cut_oid)[1]

            # if index is new, request and remember its name
            if if_index not in ipif_names:
                ipif_names[if_index] = await self._get_ipif_name(if_index)
            
            # by default, arp entry status is dynamic
            results[ipif_names[if_index]][ip] = {"mac_address": mac, "status": "dynamic"}

        # get arp entries' statuses
        for oid, status in await self._bulk_walk(self._switch_oids_config[SwitchConfigSection.ARP], ["status"]):
            # cut ip address and ipif index from oid
            cut_oid, ip = L2SwitchClient._parse_ip_address_from_oid(oid)
            if_index = SNMPClient._parse_last_index(cut_oid)[1]
            
            # if index or ip is unknown, don't count it
            if if_index in ipif_names and ip in results[ipif_names[if_index]] and status in {"other", "static"}:
                # change only those that are static
                results[ipif_names[if_index]][ip]["status"] = "static"
        
        # {ipif_name: {ip: {mac_address, status}}}
        return results
    
    ### PORT MANAGEMENT AND INFO ###

    # get any data associated with exact port by param list
    async def _get_port_data(self, port: int, include_params: list[str], prefix: str | None = None) -> ResponseData:
        # add optional prefix
        if prefix is not None:
            include_params = [f"{prefix}{param}" for param in include_params]

        # special suffix 100/101 for medium/fiber combo ports in some oids
        combo_fiber_suffix = None
        
        # if this port is combo on the switch
        if self._is_combo_port(port):
            # get all oids where is medium/fiber difference
            combo_ports_oids = set(self._switch_oids_config[SwitchConfigSection.PORT]["combo_ports_oids"])

            # if unstated which type of combo port is used and at least one of oids needs the specification, identify port type
            if self._is_combo_port_fiber(port) is None and any([
                        oid in combo_ports_oids
                        for oid in include_params
                    ]):
                await self._identify_medium_fiber_combo_port(port)
            
            # if this port type was identified as fiber, add special suffix to every param where required
            if self._is_combo_port_fiber(port):
                combo_fiber_suffix = "_combo_fiber"
                include_params = [
                    oid + combo_fiber_suffix
                    if oid in combo_ports_oids
                    else oid
                    for oid in include_params
                ]
        
        # get the results and remove suffix if found
        oid_vars = {"port": port}
        results = await self._get(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)
        if self._is_combo_port_fiber(port) and combo_fiber_suffix is not None:
            results = {key.removesuffix(combo_fiber_suffix): value for key, value in results.items()}
        
        # return in standard form {request_name: data}, excluding optional prefix
        return {key.removeprefix(prefix): value for key, value in results.items()}

    # identify, is the combo port type medium or fiber, by object fields
    async def _identify_medium_fiber_combo_port(self, port: int) -> None:
        # lock is used to prevent more that one method from trying to perform identification
        async with self._combo_ports_locks[port]:
            if self._is_combo_port_fiber(port) is None:
                # check links for medium and fiber ports
                include_params = ["link_status", "link_status_combo_fiber"]
                oid_vars = {"port": port}
                copper_fiber_statuses = await self._get(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)

                # only if fiber link is up and medium link is down, port is considered fiber
                if copper_fiber_statuses["link_status"] != "link_pass" and copper_fiber_statuses["link_status_combo_fiber"] == "link_pass":
                    self._set_combo_port_is_fiber(port, is_fiber=True)
                else:
                    self._set_combo_port_is_fiber(port, is_fiber=False)

    # get main link settings and status for port
    async def get_port_status(self, port: int) -> ResponseData:
        # checl state, speed/duplex settings and link
        include_params = ["admin_state", "speed_duplex_settings", "link_status", "speed_duplex_status"]
        result = await self._get_port_data(port, include_params)

        # merge link/speed info into one parameter showing link down or actual speed and duplex
        result["link_speed_duplex_status"] = "link_down" if result["link_status"] != "link_pass" else result["speed_duplex_status"]
        del result["link_status"]
        del result["speed_duplex_status"]

        # return modified dict
        return result

    # get advanced port management settings
    async def get_port_management(self, port: int) -> ResponseData:
        # check state, link/mac/flow control settings
        include_params = ["admin_state", "speed_duplex_settings", "flow_control", "address_learning", "mdix_state"]
        return await self._get_port_data(port, include_params)
    
    # set port management configuration
    async def set_port_management(self, request: RequestData, port: int) -> SNMPResponseCode:
        # mdix state change needs special logic and check
        mdix_state_change = True if "mdix_state" in request else False
        
        # set other parameters by default
        include_params = {param: value for param, value in request.items() if param != "mdix_state"}
        oid_vars = {"port": port}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)

            # for mdix state, send individual request
            if mdix_state_change:
                mdix_param = {"mdix_state": request["mdix_state"]}
                
                try:
                    mdix_result = await self._set(self._switch_oids_config[SwitchConfigSection.PORT], mdix_param, oid_vars)
                except SNMPTransportError:
                    # for DES-3028, mdix_state set request has timeout error, but it's ok if the value was set correctly
                    mdix_state = (await self._get_port_data(port, ["mdix_state"]))["mdix_state"]
                    if request["mdix_state"] != mdix_state:
                        raise
            
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### CABLE DIAGNOSTIC ### 

    # perform cable diagnostic for port and get the result
    async def get_cable_diagnostic_for_port(self, port: int) -> ResponseData:
        # little warning should be thrown
        print("Warning: user may lost internet connection")

        # for combo port, if unstated which type of it is used, identify
        if self._is_combo_port(port) and self._is_combo_port_fiber(port) is None:
            await self._identify_medium_fiber_combo_port(port)
        
        # for any fiber port (only fiber or combo fiber), can't perform cable diagnostic
        if self._is_combo_port_fiber(port) or self._is_fiber_port(port):
            return {"unable_to_perform": True}
        
        # start diagnostic
        param = "cable_diagnostic_action"
        include_params = {param: "action"}
        oid_vars = {"port": port}
        action_status = await self._set(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)

        # wait until finished (action = other)
        while action_status[param] in {"action", "processing"}:
            action_status = await self._get(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)
        
        # get data as {cable_diagnostic_pair1_length, cable_diagnostic_pair1_status, ...}
        include_params = [
            f"cable_diagnostic_pair{i}_{suffix}"
            for i in range(1, self._get_cable_diagnostic_pairs_count(port) + 1)
            for suffix in {"status", "length"}
        ]
        oid_vars = {"port": port}
        pairs_tests = await self._get(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)
        
        # base results parameters, no cable by default
        results = {"unable_to_perform": False, "no_cable": True}
        prefix = "cable_diagnostic_pair"

        # combine results
        results = {
            "pairs": {
                # find out actual pair number
                f"pair{self._get_actual_cable_diagnostic_pair_number(i)}": {
                    # get status and length for each pair
                    "status": pairs_tests[f"{prefix}{i}_status"],
                    "length": pairs_tests[f"{prefix}{i}_length"]
                }
                # go through pair numbers
                for i in range(1, self._get_cable_diagnostic_pairs_count(port) + 1)
            },
            "unable_to_perform": False
        }

        # no cable if all pair statuses are no cable
        results["no_cable"] = all(pair_data["status"] == "no_cable" for pair_data in results["pairs"].values())

        # {{pairs: {pair1: {status, length}, ...}}, unable_to_perform, no_cable}
        return results

    # map pair number got from snmp response with physical pair number
    def _get_actual_cable_diagnostic_pair_number(self, pair_number: int) -> int:
        # when rearrange isn't necessary, number stays the same, otherwise the scheme is:
        # response - actual
        #    1    -    3
        #    2    -    1
        #    3    -    2
        #    4    -    4
        if not self._need_to_order_cable_diagnostic_pairs or pair_number == 4:
            return pair_number
        if pair_number == 1:
            return 3
        if pair_number == 2:
            return 1
        return 2

    ### PORT SECURITY ###

    # get port security config for port
    async def get_port_security_on_port(self, port: int) -> ResponseData:
        # prefix and params
        prefix = "port_security_"
        include_params = ["max_learning_addresses", "lock_address_mode", "admin_state"]

        # return result using common port method
        return await self._get_port_data(port, include_params, prefix)
    
    # manage port security settings for port
    async def set_port_security_on_port(self, request: RequestData, port: int) -> SNMPResponseCode:
        # add prefix to all parameters
        include_params = {f"port_security_{param}": value for param, value in request.items()}
        oid_vars = {"port": port}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    # clear static fdb on port by switching port security mode on port
    async def clear_port_security_on_port(self, port: int) -> SNMPResponseCode:
        # prefix and param
        prefix = "port_security_"
        param = "lock_address_mode"
        include_params = [param]

        # get current mode and choose temporary one: delete_on_reset/permanent
        current_mode = (await self._get_port_data(port, include_params, prefix))[param]
        temp_mode = "permanent" if current_mode == "delete_on_reset" else "delete_on_reset"

        # switch to temporary mode
        result = await self.set_port_security_on_port({param: temp_mode}, port)
        # return error code if occured
        if result != SNMPResponseCode.SUCCESS:
            return result
        # switch back and return final status code
        return await self.set_port_security_on_port({param: current_mode}, port)
    
    # delete exact mac address from static fdb table on port
    async def clear_port_security_exact_mac_address(self, request: RequestData, port: int) -> SNMPResponseCode:
        # get vlan table to map vlan id with vlan name
        vlan_table = await self.get_vlan_static_table()
        
        # request includes vlan name, port, mac and action
        include_params = {
            "vlan_name": vlan_table[request["vlan_id"]]["vlan_name"],
            "port": request["port"],
            "mac_address": request["mac_address"],
            "action": "start"
        }

        # add prefix
        include_params = {f"clear_port_security_{key}": value for key, value in include_params.items()}
        oid_vars = {"port": port}

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### LOOPBACK DETECTION ###

    # get loopback detection config for port
    async def get_loopdetect_on_port(self, port: int) -> ResponseData:
        # prefix and params
        prefix = "loopdetect_"
        include_params = ["state", "status"]

        # return result using common port method
        return await self._get_port_data(port, include_params, prefix)
    
    # manage loopback detection settings for port
    async def set_loopdetect_on_port(self, request: RequestData, port: int) -> SNMPResponseCode:
        # add prefix to all parameters
        include_params = {f"loopdetect_{param}": value for param, value in request.items()}
        oid_vars = {"port": port}

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### PORT UTILIZATION ###

    # get port traffic utilization statistics
    async def get_port_utilization(self, port: int) -> ResponseData:
        # prefix and params
        prefix = "utilization_"
        include_params = ["tx_frames", "rx_frames", "percentage"]

        # return result using common port method
        return await self._get_port_data(port, include_params, prefix)
    
    ### BANDWIDTH CONTROL ###

    # get bandwidth control config for port
    async def get_bandwidth_control_on_port(self, port: int) -> ResponseData:
        # prefix and params
        prefix = "bandwidth_control_"
        include_params = ["rx_rate", "tx_rate"]

        # return result using common port method
        return await self._get_port_data(port, include_params, prefix)
    
    # manage bandwidth control settings for port
    async def set_bandwidth_control_on_port(self, request: RequestData, port: int) -> SNMPResponseCode:
        # add prefix to all parameters
        include_params = {f"bandwidth_control_{param}": value for param, value in request.items()}
        oid_vars = {"port": port}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### TRAFFIC CONTROL ###
    
    # get traffic control config for port
    async def get_traffic_control_on_port(self, port: int) -> ResponseData:
        # prefix and params
        prefix = "traffic_control_"
        include_params = ["threshold", "broadcast_status", "multicast_status", "unicast_status", "action_status", "count_down", "time_interval"]

        # return result using common port method
        return await self._get_port_data(port, include_params, prefix)
    
    # manage traffic control settings for port
    async def set_traffic_control_on_port(self, request: RequestData, port: int) -> SNMPResponseCode:
        # add prefix to all parameters
        include_params = {f"traffic_control_{param}": value for param, value in request.items()}
        oid_vars = {"port": port}
        
        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### TRAFFIC SEGMENTATION ###

    # get traffic segmentation config for port
    async def get_traffic_segmentation_for_port(self, port: int) -> ResponseData:
        # prefix and param
        prefix = "traffic_segmentation_"
        param = "forward_ports"
        include_params = [param]

        # get result using common port method
        result = await self._get_port_data(port, include_params, prefix)

        # return result parsing hex string into portlist
        portlist = L2SwitchClient._parse_assigned_ports_from_hex(result[param], self._ports_count)
        return {param: portlist}

    # manage traffic segmentation settings for port
    async def set_traffic_segmentation_for_port(self, request: RequestData, port: int) -> SNMPResponseCode:
        # add prefix, composing portlist to a hex string
        param = "forward_ports"
        include_params = {f"traffic_segmentation_{param}": L2SwitchClient._combine_assigned_ports_to_hex(request[param])}
        oid_vars = {"port": port}

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.PORT], include_params, oid_vars)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS
    
    ### PORT STATISCTICS ###

    # get all port packet statistics: speed and different packet types count
    async def get_all_packet_statistics_on_port(self, port: int) -> ResponseData:
        # speed and packet types count
        task_megabit = asyncio.create_task(self.get_rx_tx_megabit_speed_on_port())
        task_packets = asyncio.create_task(self.get_rx_tx_all_packet_types_on_port())

        # gather results
        results = await asyncio.gather(task_megabit, task_packets)
        return results[0] | results[1]
    
    # get rx/tx port speed in megabit
    async def get_rx_tx_megabit_speed_on_port(self, port: int) -> ResponseData:
        # rx and tx bytes tasks
        include_params = ["rx_bytes", "tx_bytes"]
        tasks = [asyncio.create_task(self._get_packets_speed(key)) for key in include_params]
        
        # get and return refactored results
        results = await asyncio.gather(*tasks)
        return {
            # convert bytes to megabit with replacing params suffix
            f"{key.removesuffix('bytes')}megabit": L2SwitchClient._byte_to_megabit(value)
            for res in results
            for key, value in res.items()
        }
    
    # get rx/tx all packet types: unicast, multicast, broadcast
    async def get_rx_tx_all_packet_types_on_port(self, port: int) -> ResponseData:
        # create a task for each parameter
        include_params = [
            "rx_unicast_packets", "rx_multicast_packets", "rx_broadcast_packets",
            "tx_unicast_packets", "tx_multicast_packets", "tx_broadcast_packets"
        ]
        tasks = [asyncio.create_task(self._get_packets_speed(key, port)) for key in include_params]

        # gather and return the results
        results = await asyncio.gather(*tasks)
        return {key: value for res in results for key, value in res.items()}
    
    # get different packet statistics as a time average value
    async def _get_packets_speed(self, packet_type: str, port: int) -> ResponseData:
        # params for both requests
        include_params = [packet_type]

        # get current counter value and remember start time
        start_packets = (await self._get_port_data(port, include_params))[packet_type]
        start_time = perf_counter()

        # wait a bit
        await asyncio.sleep(SNMP.PACKET_STATISTICS_PAUSE)
        
        # get new current counter value and remember end time
        end_packets = (await self._get_port_data(port, include_params))[packet_type]
        end_time = perf_counter()

        # calculate speed as a time average value and return the result
        speed = int((end_packets - start_packets) / (end_time - start_time))
        return {packet_type: speed}
    
    # get crc errors split into to categories
    async def get_crc_errors_on_port(self, port: int) -> ResponseData:
        # alignment error - when packet has wrong size
        # fcs error - while checking crc sum, when some bits are wrong
        include_params = ["alignment_errors", "fcs_errors"]
        return await self._get_port_data(port, include_params)

    # clear all counters as snmp doesn't have clear counters for port oid
    async def clear_all_counters(self) -> SNMPResponseCode:
        include_params = {"clear_all_counters": "active"}

        try:
            result = await self._set(self._switch_oids_config[SwitchConfigSection.SWITCH], include_params)
        except SNMPTransportError:
            return SNMPResponseCode.TRANSPORT_ERROR
        except SNMPProtocolError as err:
            if err.status == "inconsistentValue":
                return SNMPResponseCode.INVALID_DATA
            return SNMPResponseCode.UNKNOWN_ERROR
        return SNMPResponseCode.SUCCESS

    ### HELPER FUNCTIONS ###

    # get set of port numbers from hex string using bit operators and ports count
    @staticmethod
    def _parse_assigned_ports_from_hex(octet_string: str, ports_count: int) -> set[int]:
        num_val = int(octet_string, 16)
        return {i + 1 for i in range(ports_count) if (num_val >> (63 - i)) & 1}

    # combine set of ports to hex value as a bytearray
    @staticmethod
    def _combine_assigned_ports_to_hex(portlist: set[int]) -> bytearray:
        result = bytearray(8)

        for port in portlist:
            byte_index = (port - 1) // 8
            bit_index = (port - 1) % 8
            result[byte_index] |= 1 << (7 - bit_index)
        
        return result

    # return set of bytes numbers (starting from 0) that are fully covered with mask, mask should be without 0x
    @staticmethod
    def _parse_acl_packet_content_fully_inspected_bytes(mask: str) -> set[int]:
        return {ind for ind, byte in enumerate(bytes.fromhex(mask)) if byte == 0xFF}

    # check if ipv4 and/or arp bytes are checked with set of bytes
    @staticmethod
    def _discover_acl_packet_content_ipv4_arp_check_state(fully_inspected_bytes: set[int]) -> str:
        # find out separately that ipv4/arp are checked
        ipv4_check_state = all(byte in fully_inspected_bytes for byte in SNMP.SOURCE_IP_BYTES_IN_IPV4)
        arp_check_state = all(byte in fully_inspected_bytes for byte in SNMP.SOURCE_IP_BYTES_IN_ARP)
        
        # main variable for all states: none/ipv4/arp/both
        if ipv4_check_state:
            ipv4_arp_check_state = "both" if arp_check_state else "ipv4"
        else:
            ipv4_arp_check_state = "arp" if arp_check_state else "none"
        
        return ipv4_arp_check_state

    # parse 4-byte hex entry to ip address
    @staticmethod
    def _parse_acl_chunk_to_ip(acl_entry: str) -> str:
        return ".".join([str(int(acl_entry[2:][2*i : 2*i+2], 16)) for i in range(4)])

    # convert ip into 4-byte hex chunk
    @staticmethod
    def _convert_ip_to_acl_chunk(ip: str) -> str:
        return "".join(f"{int(octet):02x}" for octet in ip.split("."))

    # cut ip address from oid and return as ip
    @staticmethod
    def _parse_ip_address_from_oid(oid: str) -> tuple[str, str]:
        oid, *ip_address = oid.rsplit(".", 4)
        ip_address = ".".join(ip_address[-4:])
        return oid, ip_address
    
    # convert string name into oid as ASCII symbols
    @staticmethod
    def _convert_name_into_oid(name: str) -> str:
        return f"{len(name)}.{'.'.join(str(ord(sym)) for sym in name)}"

    # cut vlan id and mac from oid
    @staticmethod
    def _parse_vlan_id_mac_from_oid_suffix(oid: str) -> tuple[str, str]:
        oid, vlan_id, *mac = oid.rsplit(".", 7)

        # vlan id is integer
        vlan_id = int(vlan_id)
        # form macc address
        mac = "-".join([f"{int(octet):02X}" for octet in mac])

        # return base oid, vlan_id, mac
        return oid, vlan_id, mac
    
    # calculate megabit from bytes
    @staticmethod
    def _byte_to_megabit(bytes_count: int) -> int:
        return round(bytes_count * 8 / 1024 / 1024)