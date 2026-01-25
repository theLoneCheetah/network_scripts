#!/usr/bin/python3
import traceback
import signal
import sys
import os
from typing import Any
# user's modules
from base_handler import BaseHandler
from database_manager import DatabaseManager
from L2_switch import L2Switch
from const import Database, PacketScan


##### CLASS FOR PACKET SCANNING #####

class PacketScanHandler(BaseHandler):
    __rx_megabit: int
    __max_rx_megabit: int
    __tx_megabit: int
    __max_tx_megabit: int
    _db_manager: DatabaseManager
    _record_data: dict[str, Any]
    _L2_manager: L2Switch

    def __init__(self, usernum: int) -> None:
        # init with base constructor
        super().__init__(usernum)

        # handle signal with "kill" command and CTRL+C key for safe exiting
        signal.signal(signal.SIGTERM, self.__handle_exit)
        signal.signal(signal.SIGINT, self.__handle_exit)

        # create pipe if not exists
        if not os.path.exists(PacketScan.PIPE):
            os.mkfifo(PacketScan.PIPE)

        # variables
        self.__rx_megabit = 0
        self.__max_rx_megabit = 0
        self.__tx_megabit = 0
        self.__max_tx_megabit = 0

    # handler for safe exiting, gets signal number and stack frame and exits successfully
    def __handle_exit(self, sig, frame) -> None:
        sys.exit(0)

    # main function
    def check_packet(self) -> None:
        # get data from database for switch connection
        try:
            self.__get_switch_port()
        except Exception:   # exception while checking record
            print("Exception while working with the database record:")
            traceback.print_exc()

        # scan packet on switch and provide data for bash script by pipe
        try:
            self.__scan_packet()
        # exceptions while working with L2, show traceback
        except Exception:
            print("Exception while working with equipment:")
            traceback.print_exc()

    # working with database
    def __get_switch_port(self) -> None:
        try:
            # connect and get user's switch and port from database
            self._db_manager = DatabaseManager()
            dict_data = self._db_manager.get_switch_port(self._usernum)
            self._record_data = {Database.KEY_FIELD[key]: value for key, value in dict_data.items()}
        
        finally:   # always close connection and delete database manager
            del self._db_manager
    
    # check and write packet to named pipe
    def __scan_packet(self) -> None:
        # calculate megabit and max megabit
        def calculate_current_and_max(rx_bytes: int, tx_bytes: int) -> None:
            self.__rx_megabit = BaseHandler._byte_to_megabit(rx_bytes)
            self.__tx_megabit = BaseHandler._byte_to_megabit(tx_bytes)
            self.__max_rx_megabit = max(self.__max_rx_megabit, self.__rx_megabit)
            self.__max_tx_megabit = max(self.__max_tx_megabit, self.__tx_megabit)

        try:
            # connect to switch
            self._L2_manager = L2Switch(self._record_data["switch"], self._record_data["port"])
            
            # open pipe with buffering by every line, not to collect lines in python script's buffer
            with open(PacketScan.PIPE, "w", buffering=1) as pipe:
                # run until interrupted
                while True:
                    # get bytes and calculate megabit with max
                    calculate_current_and_max(*self._L2_manager.get_packets_port())

                    # try block needed because bash script always reads data from pipe and closes promtply
                    try:
                        # write rx, rx_max, tx, tx_max with spaces in one string into pipe
                        pipe.write(f"{self.__rx_megabit} {self.__max_rx_megabit} {self.__tx_megabit} {self.__max_tx_megabit}\n")

                        # forcely write data from buffer into pipe
                        pipe.flush()
                    
                    # ignore broken pipe error when bash is not reading
                    except BrokenPipeError:
                        pass
        
        # catch error for correct exiting: eof ending, broken pipe by bash, exit from bash
        except (EOFError, BrokenPipeError, SystemExit):
            pass
            
        # always close connection and delete L2 and L3 managers
        finally:
            del self._L2_manager
