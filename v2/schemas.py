#!/usr/bin/python3
from pydantic import BaseModel, Field
from typing import Annotated, Literal

### BASE MODEL CONFIG ###

class RestrictedBaseModel(BaseModel):
    # disallow any extra fields in configs
    model_config = {"extra": "forbid"}

### L2 SWITCH SCHEMAS ###

class FloodFdbConfig(RestrictedBaseModel):
    state: str | None = None

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

class LoopdetectConfig(RestrictedBaseModel):
    state: str | None = None

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