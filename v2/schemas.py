#!/usr/bin/python3
from pydantic import BaseModel, Field
from typing import Annotated

class PortSecurityConfig(BaseModel):
    max_learning_addresses: Annotated[int, Field(gt=0, le=64)] | None = None
    lock_address_mode: str | None = None
    admin_state: str | None = None

class BandwidthControlConfig(BaseModel):
    rx_rate: Annotated[int, Field(gt=0, le=1024000)] | None = None
    tx_rate: Annotated[int, Field(gt=0, le=1024000)] | None = None


