#!/usr/bin/python3
from typing import TypedDict, Any
import pymysql.cursors
import os
# user's modules
from const import Database

# typed dict class for result of switch-port query
class SwitchPortData(TypedDict):
    switchP: str
    PortP: int


##### MAIN QUERIES #####

class Queries:
    GET_MAIN_RECORD = "SELECT Number, Vznos, IP, Masck, Gate, switchP, PortP, dhcp_type, Add_IP, Number_serv, Number_net, Street, House FROM users WHERE Number = %s"
    GET_USERNUMS_BY_SWITCH_PORT = "SELECT Number FROM users WHERE switchP = %s AND PortP = %s"
    GET_USERNUMS_BY_IP = "SELECT Number FROM users WHERE IP = %s"
    GET_USERNUMS_BY_PUBLIC_IP = "SELECT Number FROM users WHERE Add_IP = %s"
    GET_SWITCH_PORT = "SELECT switchP, PortP FROM users WHERE Number = %s"

##### CLASS TO GET DATA FROM THE DATABASE #####

class DatabaseManager:
    __SERVER: str
    __DATABASE: str
    __USER: str
    __PASSWORD: str
    __CHARSET: str
    __connection: pymysql.Connection
    
    # init data and connect to database
    def __init__(self) -> None:
        self.__SERVER = os.getenv("DB_SERVER")
        self.__DATABASE = os.getenv("DB_NAME")
        self.__USER = os.getenv("DB_USER")
        self.__PASSWORD = os.getenv("DB_PASSWORD")
        self.__CHARSET = os.getenv("DB_CHARSET")
        
        # start session
        self.__start_connection()
    
    # start
    def __start_connection(self) -> None:
        print("Connecting to database...")
        self.__connection = pymysql.connect(host=self.__SERVER,
                                            user=self.__USER,
                                            password=self.__PASSWORD,
                                            database=self.__DATABASE,
                                            charset=self.__CHARSET,
                                            cursorclass=pymysql.cursors.DictCursor)
        print("Success")
    
    # delete, close connection
    def __del__(self) -> None:
        print("Closing connection to database...")
        self.__connection.close()
        print("Success")
    
    # get main data about this user
    def get_main_record(self, usernum: int) -> dict[str, Any]:
        with self.__connection.cursor() as cursor:
            cursor.execute(Queries.GET_MAIN_RECORD, (usernum,))
            return cursor.fetchone()
    
    # find users on this switch and port
    def get_usernum_by_switch_port(self, switch: str, port: int) -> list[int]:
        with self.__connection.cursor() as cursor:
            cursor.execute(Queries.GET_USERNUMS_BY_SWITCH_PORT, (switch, port))
            return [row[Database.USERNUM] for row in cursor.fetchall()]
    
    # find users with this ip
    def get_usernum_by_ip(self, ip: str) -> list[int]:
        with self.__connection.cursor() as cursor:
            cursor.execute(Queries.GET_USERNUMS_BY_IP, (ip,))
            return [row[Database.USERNUM] for row in cursor.fetchall()]
    
    # find users with this public ip
    def get_usernum_by_public_ip(self, ip: str) -> list[int]:
        with self.__connection.cursor() as cursor:
            cursor.execute(Queries.GET_USERNUMS_BY_PUBLIC_IP, (ip,))
            return [row[Database.USERNUM] for row in cursor.fetchall()]
    
    # get switch and port for user
    def get_switch_port(self, usernum: int) -> SwitchPortData:
        with self.__connection.cursor() as cursor:
            cursor.execute(Queries.GET_SWITCH_PORT, (usernum,))
            return cursor.fetchone()