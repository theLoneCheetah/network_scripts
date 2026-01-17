#!/usr/bin/python3
from __future__ import annotations
from typing import TYPE_CHECKING, Any
from abc import ABC, abstractmethod
# user's modules
from const import Const
from protocols import L2SwitchProtocol

# import as type only by Pylance (for VS Code)
if TYPE_CHECKING:
    from database_manager import DatabaseManager


##### ABSTRACT HANDLER CLASS FOR USER #####

class BaseHandler(ABC):
    # annotations of objects in child classes: database and L2 managers, record data dict
    _db_manager: DatabaseManager
    _switch_manager: L2SwitchProtocol
    _record_data: dict[str, Any]

    # abstract constructor so base class is abstract
    @abstractmethod
    def __init__(self, usernum):
        # init by usernum
        self._usernum = usernum
    
    # print all fields
    def print_record(self):
        print("-" * 20)
        
        # print usernum and other fields
        print(f"{Const.USERNUM}:{' '*(12-len(Const.USERNUM))}{self._usernum}")
        for key in self._record_data:
            print(f"{key}:{' '*(12-len(key))}{self._record_data[key]}")
        
        print("-" * 20)
    
    # static method to calculate megabit from bytes
    @staticmethod
    def _byte_to_megabit(bytes_count):
        return round(bytes_count * 8 / 1024 / 1024)