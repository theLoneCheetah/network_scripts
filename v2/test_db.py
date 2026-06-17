#!/usr/bin/python3
import pymysql.cursors
import os
# user's modules
from const import Database, Country

class TestDatabaseManager:
    def __init__(self) -> None:
        self.__SERVER = os.getenv("DB_SERVER")
        self.__DATABASE = os.getenv("DB_NAME")
        self.__USER = os.getenv("DB_USER")
        self.__PASSWORD = os.getenv("DB_PASSWORD")
        self.__CHARSET = os.getenv("DB_CHARSET")
        
        # start session
        self.__start_connection()
    
    # delete, close connection
    def __del__(self) -> None:
        print("Closing connection to database...")
        self.__connection.close()
        print("Success")
    
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
    
    # get main data about this user
    def get_switches(self, model):
        with self.__connection.cursor() as cursor:
            cursor.execute("SELECT IP FROM users WHERE Vznos = 59 AND FIO = %s", (model,))
            return cursor.fetchall()
    
    def get_empty_switches(self, model):
        switches = self.get_switches(model)
        result = []

        with self.__connection.cursor() as cursor:
            for switch in switches:
                ip = switch["IP"]
                cursor.execute("SELECT COUNT(*) AS count FROM users WHERE switchP = %s", (ip,))
                if cursor.fetchone()["count"] == 0:
                    result.append(ip)
        
        return result
    
    # get main data about this user
    def get_users_by_switches(self, switch):
        with self.__connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM users WHERE switchP = %s", (switch,))
            return cursor.fetchall()
    
    def get_switches_by_model(self, model):
        with self.__connection.cursor() as cursor:
            cursor.execute("SELECT IP FROM users WHERE Vznos = 59 AND FIO = %s", (model,))
            return {switch["IP"] for switch in cursor.fetchall()}
    
    def get_random_usernums(self):
        with self.__connection.cursor() as cursor:
            cursor.execute("SELECT Number FROM users WHERE Number_net = %s ORDER BY RAND() LIMIT 20", (Country.NSERV_NNET,))
            return [row[Database.USERNUM] for row in cursor.fetchall()]
    
    def get_users_last_today_from_pseudo_L3(self):
        with self.__connection.cursor() as cursor:
            cursor.execute("SELECT Number, Gate FROM users WHERE DATE(Last_oplatcheno) IN ('2026-05-25', '2026-05-26') AND Gate = switchP AND Number_net != %s", (Country.NSERV_NNET,))
            results = [{**row} for row in cursor.fetchall()]

            for res in results:
                cursor.execute("SELECT COUNT(*) AS COUNT FROM users WHERE Gate = %s AND (Vznos > 100 OR Vznos = 52) GROUP BY Gate", (res["Gate"],))
                res |= cursor.fetchall()[0]
            
            return sorted(results, key=lambda x: x["COUNT"])

if __name__ == "__main__":
    db = TestDatabaseManager()
    random_usernums = db.get_random_usernums()
    print(random_usernums)