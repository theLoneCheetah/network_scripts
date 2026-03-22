#!/usr/bin/python3
from __future__ import annotations
from typing import TYPE_CHECKING, Any
from abc import ABC, abstractmethod
# user's modules
from const import Database
from protocols import L2Protocol

# import as type only by Pylance (for VS Code)
if TYPE_CHECKING:
    from database_manager import DatabaseManager


##### ABSTRACT HANDLER CLASS FOR USER #####

class BaseHandler(ABC):
    # annotation of usernum
    _usernum: int
    # annotations of objects in child classes: database and L2 managers, record data dict
    _db_manager: DatabaseManager
    _L2_manager: L2Protocol
    _record_data: dict[str, Any]

    # abstract constructor so base class is abstract
    @abstractmethod
    def __init__(self, usernum: int) -> None:
        # init by usernum
        self._usernum = usernum
    
    # print all fields
    def print_record(self) -> None:
        print("-" * 20)
        
        # print usernum and other fields
        print(f"{Database.USERNUM}:{' '*(12-len(Database.USERNUM))}{self._usernum}")
        for key, val in self._record_data.items():
            print(f"{key}:{' '*(12-len(key))}{val}")
        
        print("-" * 20)
    
    # static method to calculate megabit from bytes
    @staticmethod
    def _byte_to_megabit(bytes_count: int) -> int:
        return round(bytes_count * 8 / 1024 / 1024)