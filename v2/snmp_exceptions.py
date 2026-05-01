#!/usr/bin/python3
from enum import Enum

class SNMPResponseCode(Enum):
    SUCCESS = (0, "Успешно")
    TRANSPORT_ERROR = (1, "Ошибка связи")
    INVALID_DATA = (2, "Ошибка в параметрах запроса")
    UNKNOWN_ERROR = (3, "Неизвестная ошибка")

class SNMPTransportError(Exception):
    def __init__(self, error_message) -> None:
        super().__init__()
        self._message = error_message
    
    def __str__(self) -> str:
        return f"Transport SNMP error: {self._message}"

class SNMPProtocolError(Exception):
    def __init__(self, errorStatus, errorIndex, command_names: list[str]) -> None:
        super().__init__()
        self._status = errorStatus
        self._failed_command = command_names[errorIndex - 1]

    @property
    def status(self) -> str:
        return self._status
    
    def __str__(self) -> str:
        return f"Protocol SNMP error: {self._status}. Failed command: {self._failed_command}"