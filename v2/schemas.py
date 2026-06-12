#!/usr/bin/python3
import re
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_extra_types.mac_address import MacAddress
from ipaddress import IPv4Address
from datetime import datetime
from typing import Annotated, Literal, Self

VALIDATE_DEFINITION = {"check_defined": True}
MAC_ADDRESS_REGEX = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

### BASE MODEL CONFIG ###

class RestrictedBaseModel(BaseModel):
    # disallow any extra fields in configs
    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def check_at_least_one_marked_field_is_defined(self) -> Self:
        # all fields in model that are marked
        marked_fields = {
            field_name
            for field_name, field_info in self.model_fields.items()
            if field_info.json_schema_extra and field_info.json_schema_extra.get("check_defined")
        }
        # don't check for models without tags
        if not marked_fields:
            return self
        
        # is there at least one marked field that is defined
        has_at_least_one_defined = any(
            field in marked_fields and getattr(self, field) is not None
            for field in self.model_fields_set
        )
        
        # if not, raise error
        if not has_at_least_one_defined:
            raise ValueError("At least one parameter must be defined")
        return self

### L2 SWITCH SCHEMAS ###

class SystemRebootConfig(RestrictedBaseModel):
    system_reboot_mode: str

class SaveConfig(RestrictedBaseModel):
    save_action: str

class SwitchNetworkConfig(RestrictedBaseModel):
    ip: str | None = None
    mask: str | None = None
    default_gateway: str | None = None
    management_vlan_id: Annotated[int | None, Field(ge=1, le=4094)] = None

    @field_validator("ip", "default_gateway")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        if value is None:
            return None
        IPv4Address(value)
        return value

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

class AddTrustedHostConfig(RestrictedBaseModel):
    ip: str
    mask: str

class DeleteTrustedHostConfig(RestrictedBaseModel):
    host_index: int

class CreateAclEthernetMask(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]
    use_vlan: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    source_mac_mask: Annotated[str | None, Field(pattern=MAC_ADDRESS_REGEX,
                                                 json_schema_extra=VALIDATE_DEFINITION)] = None
    destination_mac_mask: Annotated[str | None, Field(pattern=MAC_ADDRESS_REGEX,
                                                      json_schema_extra=VALIDATE_DEFINITION)] = None
    use_802_1p: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    use_ethernet_type: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None

class DeleteAclMask(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]

class AddAclEthernetRule(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]
    access_id: Annotated[int, Field(ge=1, le=65535)]
    vlan_name: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    source_mac: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    destination_mac: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    check_802_1p: Annotated[int | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    ethernet_type: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    local_priority: Annotated[int | None, Field(ge=0, le=7)] = None
    permit: str
    ports: set[int]
    rx_rate: Annotated[int | None, Field(ge=64, le=1024000)] = None

class DeleteAclRule(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]
    access_id: Annotated[int, Field(ge=1, le=65535)]

class CreateAclPacketContentMask(RestrictedBaseModel):
    profile_id: Annotated[int, Field(ge=1, le=256)]
    offset_0_15: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    offset_16_31: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    offset_32_47: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    offset_48_63: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None
    offset_64_79: Annotated[str | None, Field(json_schema_extra=VALIDATE_DEFINITION)] = None

class CreateVlanConfig(RestrictedBaseModel):
    vlan_id: int
    vlan_name: str

# class RenameVlanConfig(RestrictedBaseModel):
#     vlan_id: int
#     vlan_name: str

class DeleteVlanConfig(RestrictedBaseModel):
    vlan_id: int

class AddVlanOnPortsConfig(RestrictedBaseModel):
    vlan_id: int
    portlist: set[int]
    status: str

class DeleteVlanFromPortsConfig(RestrictedBaseModel):
    vlan_id: int
    portlist: set[int]

class FloodFdbConfig(RestrictedBaseModel):
    state: str

class DhcpRelayConfig(RestrictedBaseModel):
    state: str | None = None
    hop_count: Annotated[int | None, Field(ge=1, le=16)] = None
    time_threshold: Annotated[int | None, Field(ge=0, le=65535)] = None
    option82_state: str | None = None
    option82_check_state: str | None = None
    option82_policy: str | None = None
    option82_remote_id_type: str | None = None
    option82_remote_id: str | None = None

class ManageDhcpServersForIpifConfig(RestrictedBaseModel):
    ipif_servers: dict[str, set[str]]

### L2 PORT SCHEMAS ###

class PortManagementConfig(RestrictedBaseModel):
    admin_state: str | None = None
    speed_duplex_settings: str | None = None
    flow_control: str | None = None
    address_learning: str | None = None
    mdix_state: str | None = None

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

class LoopdetectConfig(RestrictedBaseModel):
    state: str 

class BandwidthControlConfig(RestrictedBaseModel):
    rx_rate: Annotated[int | None, Field(ge=64, le=1024000)] = None
    tx_rate: Annotated[int | None, Field(ge=64, le=1024000)] = None

class TrafficControlConfig(RestrictedBaseModel):
    threshold: Annotated[int | None, Field(ge=64, le=1000000)] = None
    broadcast_status: str | None = None
    multicast_status: str | None = None
    unicast_status: str | None = None
    action_status: str | None = None
    count_down: Literal[0] | Annotated[int | None, Field(ge=5, le=30)] = None
    time_interval: Annotated[int | None, Field(ge=5, le=30)] = None

class TrafficSegmentationConfig(RestrictedBaseModel):
    forward_ports: set[int]