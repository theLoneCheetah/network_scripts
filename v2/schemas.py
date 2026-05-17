#!/usr/bin/python3
import re
from pydantic import BaseModel, Field, field_validator
from pydantic_extra_types.mac_address import MacAddress
from ipaddress import IPv4Address
from datetime import datetime
from typing import Annotated, Literal

### BASE MODEL CONFIG ###

class RestrictedBaseModel(BaseModel):
    # disallow any extra fields in configs
    model_config = {"extra": "forbid"}

### L2 SWITCH SCHEMAS ###

class SystemRebootConfig(RestrictedBaseModel):
    system_reboot_mode: str

class SwitchNetworkConfig(RestrictedBaseModel):
    ip: str | None = None
    mask: str | None = None
    default_gateway: str | None = None
    management_vlan_id: Annotated[int, Field(ge=1, le=4094)] | None = None

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

# helper class for other vlan configs
class VlanInfo(RestrictedBaseModel):
    vlan_id: int
    vlan_name: str

class CreateVlanConfig(RestrictedBaseModel):
    vlan: VlanInfo

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

### L2 PORT SCHEMAS ###

class PortManagementConfig(RestrictedBaseModel):
    admin_state: str | None = None
    speed_duplex_settings: str | None = None
    flow_control: str | None = None
    address_learning: str | None = None
    mdix_state: str | None = None

class PortSecurityConfig(RestrictedBaseModel):
    max_learning_addresses: Annotated[int, Field(ge=0, le=64)] | None = None
    lock_address_mode: str | None = None
    admin_state: str | None = None

# helper class for clear port security by mac addresses class
class MacAddressConfig(RestrictedBaseModel):
    vlan_id: Annotated[int, Field(ge=1, le=4094)]
    port: Annotated[int, Field(ge=1, le=52)]
    mac_address: str

    @field_validator("mac_address")
    @classmethod
    def validate_mac(cls, value: str) -> str:
        mac_regex = re.compile("([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")
        if not mac_regex.match(value):
            raise ValueError()
        return value

class ClearPortSecurityExactMacAddressesConfig(RestrictedBaseModel):
    mac_addresses_list: list[MacAddressConfig]

class LoopdetectConfig(RestrictedBaseModel):
    state: str 

class BandwidthControlConfig(RestrictedBaseModel):
    rx_rate: Annotated[int, Field(ge=64, le=1024000)] | None = None
    tx_rate: Annotated[int, Field(ge=64, le=1024000)] | None = None

class TrafficControlConfig(RestrictedBaseModel):
    threshold: Annotated[int, Field(ge=64, le=1000000)] | None = None
    broadcast_status: str | None = None
    multicast_status: str | None = None
    unicast_status: str | None = None
    action_status: str | None = None
    count_down: Literal[0] | Annotated[int, Field(ge=5, le=30)] | None = None
    time_interval: Annotated[int, Field(ge=5, le=30)] | None = None

class TrafficSegmentationConfig(RestrictedBaseModel):
    forward_ports: set[int]