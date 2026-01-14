#!/usr/bin/python3
import pymysql.cursors
import os
# user's modules
from const import Const


##### MAIN QUERIES #####

class Queries:
    GET_MAIN_RECORD = "SELECT Number, Vznos, IP, Masck, Gate, switchP, PortP, dhcp_type, Add_IP, Number_serv, Number_net, Street, House FROM users WHERE Number = %s"
    GET_USERNUMS_BY_SWITCH_PORT = "SELECT Number FROM users WHERE switchP = %s AND PortP = %s"
    GET_USERNUMS_BY_IP = "SELECT Number FROM users WHERE IP = %s"
    GET_SWITCH_PORT = "SELECT switchP, PortP FROM users WHERE Number = %s"

##### CLASS TO GET DATA FROM THE DATABASE #####

class DatabaseManager:
    # init data and connect to database
    def __init__(self):
        self.__SERVER = os.getenv("DB_SERVER")
        self.__DATABASE = os.getenv("DB_NAME")
        self.__USER = os.getenv("DB_USER")
        self.__PASSWORD = os.getenv("DB_PASSWORD")
        self.__CHARSET = os.getenv("DB_CHARSET")
        
        # start session
        self.__start_connection()
    
    # delete, close connection
    def __del__(self):
        print("Closing connection...")
        self.__connection.close()
        print("Success")
    
    # start
    def __start_connection(self):
        print("Connecting to database...")
        self.__connection = pymysql.connect(host=self.__SERVER,
                                            user=self.__USER,
                                            password=self.__PASSWORD,
                                            db=self.__DATABASE,
                                            charset=self.__CHARSET,
                                            cursorclass=pymysql.cursors.DictCursor)
        print("Success")
    
    # get main data about this user
    def get_main_record(self, usernum):
        with self.__connection.cursor() as cursor:
            cursor.execute(Queries.GET_MAIN_RECORD, (usernum,))
            return cursor.fetchone()
    
    # find users on this switch and port
    def get_usernum_by_switch_port(self, switch, port):
        with self.__connection.cursor() as cursor:
            cursor.execute(Queries.GET_USERNUMS_BY_SWITCH_PORT, (switch, port))
            return [row[Const.USERNUM] for row in cursor.fetchall()]
    
    # find users with this ip
    def get_usernum_by_ip(self, ip):
        with self.__connection.cursor() as cursor:
            cursor.execute(Queries.GET_USERNUMS_BY_IP, (ip,))
            return [row[Const.USERNUM] for row in cursor.fetchall()]
    
    # get switch and port for user
    def get_switch_port(self, usernum):
        with self.__connection.cursor() as cursor:
            cursor.execute(Queries.GET_SWITCH_PORT, (usernum,))
            return cursor.fetchone()