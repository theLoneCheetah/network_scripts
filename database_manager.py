#!/usr/bin/python3
import pymysql.cursors
import os
# user's modules
from const import CONST


##### CLASS TO GET DATA FROM THE DATABASE #####

class DatabaseManager:
    # init data and connect to database
    def __init__(self):
        self.__SERVER = os.getenv("DB_SERVER")
        self.__DATABASE = os.getenv("DB_NAME")
        self.__USER = os.getenv("DB_USER")
        self.__PASSWORD = os.getenv("DB_PASSWORD")
        self.__CHARSET = os.getenv("DB_CHARSET")
        
        # basic query gets all important fields
        self.__get_query = "SELECT Number, Vznos, IP, Masck, Gate, switchP, PortP, dhcp_type, Add_IP, Number_serv, Number_net, Street, House FROM users WHERE Number = %s"
        self.__start_connection()
    
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
    
    # get data about this user
    def get_record(self, usernum):
        with self.__connection.cursor() as cursor:
            cursor.execute(self.__get_query, (usernum,))
            return cursor.fetchone()
    
    # find users on this switch and port
    def get_usernum_by_switch_port(self, switch, port):
        with self.__connection.cursor() as cursor:
            cursor.execute("SELECT Number FROM users WHERE switchP = %s AND PortP = %s", (switch, port))
            return [row[CONST.usernum] for row in cursor.fetchall()]
    
    # find users with this ip
    def get_usernum_by_ip(self, ip):
        with self.__connection.cursor() as cursor:
            cursor.execute("SELECT Number FROM users WHERE IP = %s", (ip,))
            return [row[CONST.usernum] for row in cursor.fetchall()]
    
    # end
    def __close_connection(self):
        print("Closing connection...")
        self.__connection.close()
        print("Success")
    
    # delete
    def __del__(self):
        self.__close_connection()