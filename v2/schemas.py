#!/usr/bin/python3
import re
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_extra_types.mac_address import MacAddress
from ipaddress import IPv4Address
from datetime import datetime
from typing import Annotated, Literal, Self

INCLUSIVELY_NECESSARY_FIELD_SCHEMA = {"inclusively_necessary": True}
EXCLUSIVELY_NECESSARY_FIELD_SCHEMA = {"exclusively_necessary": True}

MAC_ADDRESS_REGEX = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

### BASE MODEL CONFIG ###

class RestrictedBaseModel(BaseModel):
    # disallow any extra fields in configs
    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def check_field_groups(self) -> Self:
        inclusively_necessary = set()
        exclusively_necessary = set()

        # compose separate sets for different groups
        for field_name, field_info in self.model_fields.items():
            if extra_schema := field_info.json_schema_extra:
                if extra_schema.get("inclusively_necessary"):
                    inclusively_necessary.add(field_name)
                if extra_schema.get("exclusively_necessary"):
                    exclusively_necessary.add(field_name)

        # all fields in model that are marked
        all_marked = inclusively_necessary.union(exclusively_necessary)
        
        # all defined not None fields in model that are marked
        all_defined_marked = {
            field
            for field in self.model_fields_set.intersection(all_marked)
            if getattr(self, field) is not None
        }

        # if doesn't have any inclusively necessary fields, raise error
        if inclusively_necessary:
            defined_inclusively_necessary = all_defined_marked.intersection(inclusively_necessary)
            if not defined_inclusively_necessary:
                raise ValueError("At least one of necessary parameters must be defined")
        
        # if not exactly one exclusively necessary field is defined, raise
        if exclusively_necessary:
            defined_exclusively_necessary = all_defined_marked.intersection(exclusively_necessary)
            if len(defined_exclusively_necessary) != 1:
                raise ValueError("Exactly one of exclusively necessary parameters must be defined")
            
        return self
    
### SWITCH MANAGEMENT AND INFO ###

class SystemRebootConfig(RestrictedBaseModel):
    system_reboot_mode: str

class SaveConfig(RestrictedBaseModel):
    save_action: str

class SwitchNetworkConfig(RestrictedBaseModel):
    ip: str | None = None
    mask: str | None = None
    default_gateway: str | None = None
    management_vlan_id: Annotated[int | None, Field(ge=1, le=4094)] = None

    # ip and default gateway should be correct ip addresses
    @field_validator("ip", "default_gateway")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        if value is None:
            return None
        IPv4Address(value)
        return value

    # mask should be strictly a mask with leading ones
    @field_validator("mask")
    @classmethod
    def validate_mask(cls, value: str) -> str:
        mask_length = int(IPv4Address(value))
        inverted = ~mask_length & 0xFFFFFFFF
        check = (inverted + 1) & inverted
        if mask_length == 0 or check != 0:
            raise ValueError()
        return value

class CurrentTimeConfig(RestrictedBaseModel):
    current_time: datetime

### TRUSTED HOST ###

class AddTrustedHostConfig(RestrictedBaseModel):
    host_index: int | None = None
    ip: str
    mask: str

class DeleteTrustedHostConfig(RestrictedBaseModel):
    host_index: int

### ACL ###

# create new acl ethernet mask
class AclEthernetMaskAdvancedConfig(RestrictedBaseModel):
    use_vlan: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    source_mac_mask: Annotated[str | None, Field(pattern=MAC_ADDRESS_REGEX,
                                                 json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    destination_mac_mask: Annotated[str | None, Field(pattern=MAC_ADDRESS_REGEX,
                                                      json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    use_802_1p: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    use_ethernet_type: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None

class CreateAclEthernetMaskConfig(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]
    advanced_params: Annotated[AclEthernetMaskAdvancedConfig | None,
                               Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    source_mac_false_check_state: Annotated[bool | None, Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None

# create new acl packet content mask
class AclPacketContentMaskAdvancedOffsetConfig(RestrictedBaseModel):
    offset_0_15: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    offset_16_31: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    offset_32_47: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    offset_48_63: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    offset_64_79: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None

class AclPacketContentMaskAdvancedConfig(RestrictedBaseModel):
    offset_masks: Annotated[AclPacketContentMaskAdvancedOffsetConfig | None,
                            Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    general_mask: Annotated[str | None, Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    fully_inspected_bytes: Annotated[set[int] | None, Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None

class CreateAclPacketContentMaskConfig(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]
    advanced_params: Annotated[AclPacketContentMaskAdvancedConfig | None,
                               Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    ipv4_arp_check_state: Annotated[str | None, Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None

# add new acl ethernet rule
class AclEthernetRuleAdvancedConfig(RestrictedBaseModel):
    vlan_name: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    source_mac: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    destination_mac: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    check_802_1p: Annotated[int | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    ethernet_type: Annotated[str | None, Field(json_schema_extra=INCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    permit: str
    local_priority: Annotated[int | None, Field(ge=0, le=7)] = None
    rx_rate: Annotated[int | None, Field(ge=64, le=1024000)] = None

class AddAclEthernetRuleConfig(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]
    access_id: Annotated[int, Field(ge=1, le=65535)]
    advanced_params: Annotated[AclEthernetRuleAdvancedConfig | None,
                               Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    deny_any_frame: Annotated[bool | None, Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    ports: set[int]

# add new acl packet content rule
class AclPacketContentRuleAdvancedConfig(RestrictedBaseModel):
    offsets: Annotated[dict[Annotated[int, Field(ge=0, le=76)], str], Field(min_length=1, max_length=5)]
    local_priority: Annotated[int | None, Field(ge=0, le=7)] = None
    permit: str
    rx_rate: Annotated[int | None, Field(ge=64, le=1024000)] = None

class AclPacketContentRuleCustomConfig(RestrictedBaseModel):
    ipv4_arp_check_state: str
    source_ip: str

class AddAclPacketContentRuleConfig(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]
    access_id: Annotated[int, Field(ge=1, le=65535)]
    advanced_params: Annotated[AclPacketContentRuleAdvancedConfig | None,
                               Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    custom_params: Annotated[AclPacketContentRuleCustomConfig | None,
                             Field(json_schema_extra=EXCLUSIVELY_NECESSARY_FIELD_SCHEMA)] = None
    ports: set[int]

# mask/rule deleting
class DeleteAclMaskConfig(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]

class DeleteAclRuleConfig(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]
    access_id: Annotated[int, Field(ge=1, le=65535)]

### VLAN ###

class CreateVlanConfig(RestrictedBaseModel):
    vlan_id: int
    vlan_name: str

class DeleteVlanConfig(RestrictedBaseModel):
    vlan_id: int

class AddVlanOnPortsConfig(RestrictedBaseModel):
    vlan_id: int
    portlist: set[int]
    status: str

class DeleteVlanFromPortsConfig(RestrictedBaseModel):
    vlan_id: int
    portlist: set[int]

# class RenameVlanConfig(RestrictedBaseModel):
#     vlan_id: int
#     vlan_name: str

### FLOOD FDB ###

class FloodFdbConfig(RestrictedBaseModel):
    state: str

### DHCP RELAY ###

class DhcpRelayConfig(RestrictedBaseModel):
    state: str | None = None
    hop_count: Annotated[int | None, Field(ge=1, le=16)] = None
    time_threshold: Annotated[int | None, Field(ge=0, le=65535)] = None
    option82_state: str | None = None
    option82_check_state: str | None = None
    option82_policy: str | None = None
    option82_remote_id_type: str | None = None
    option82_remote_id: str | None = None

class ManageDhcpServerForIpifConfig(RestrictedBaseModel):
    ipif_name: str
    server: str

### PORT MANAGEMENT AND INFO ###

class PortManagementConfig(RestrictedBaseModel):
    admin_state: str | None = None
    speed_duplex_settings: str | None = None
    flow_control: str | None = None
    address_learning: str | None = None
    mdix_state: str | None = None

### PORT SECURITY ###

class PortSecurityConfig(RestrictedBaseModel):
    max_learning_addresses: Annotated[int | None, Field(ge=0, le=64)] = None
    lock_address_mode: str | None = None
    admin_state: str | None = None

# helper class for clear port security by mac addresses class
class FdbMacAddressConfig(RestrictedBaseModel):
    vlan_id: Annotated[int, Field(ge=1, le=4094)]
    port: Annotated[int, Field(ge=1, le=52)]
    mac_address: Annotated[str, Field(pattern=MAC_ADDRESS_REGEX)]

class ClearPortSecurityExactMacAddressesConfig(RestrictedBaseModel):
    mac_addresses_list: list[FdbMacAddressConfig]

### LOOPBACK DETECTION ###

class LoopdetectConfig(RestrictedBaseModel):
    state: str 

### BANDWIDTH CONTROL ###

class BandwidthControlConfig(RestrictedBaseModel):
    rx_rate: Annotated[int | None, Field(ge=64, le=1024000)] = None
    tx_rate: Annotated[int | None, Field(ge=64, le=1024000)] = None

### TRAFFIC CONTROL ###

class TrafficControlConfig(RestrictedBaseModel):
    threshold: Annotated[int | None, Field(ge=64, le=1000000)] = None
    broadcast_status: str | None = None
    multicast_status: str | None = None
    unicast_status: str | None = None
    action_status: str | None = None
    count_down: Literal[0] | Annotated[int | None, Field(ge=5, le=30)] = None
    time_interval: Annotated[int | None, Field(ge=5, le=30)] = None

### TRAFFIC SEGMENTATION ###

class TrafficSegmentationConfig(RestrictedBaseModel):
    forward_ports: set[int]