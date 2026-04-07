#!/usr/bin/python3
import asyncio
from typing import override, Any
from pysnmp.hlapi.v3arch.asyncio import *
from snmp_client import SNMPClient
from const import SNMP

class L2SwitchClient(SNMPClient):
    _port: int
    _model: str
    _switch_config: dict[str, Any]
    
    def __init__(self, ipaddress: str, port: int, model: str) -> None:
        super().__init__(ipaddress)
        self._port = port
        self._model = model
        self._switch_config = self._config["models"][self._model]["oids"]
    
    async def get_switch_info(self, include_oids: list[str]) -> None:
        return await self._get(self._filter_request_config(self._switch_config["switch"], include_oids))

    async def get_port_diagnostics(self, include_oids: list[str]) -> None:
        return await self._get(self._filter_request_config(self._switch_config["port"], include_oids))

    @override
    def _render_oid(self, oid: str) -> str:
        return oid.format(port=self._port)
    