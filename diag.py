#!/usr/bin/python3
import traceback
import time
# user's modules
from diag_handler import DiagHandler
from city_diag_handler import CityDiagHandler
from country_diag_handler import CountryDiagHandler
from test_db import TestDatabaseManager


##### START DIAGNOSTICS #####

def main(usernum: int = None) -> None:
    # get usernum
    if usernum is None:
        usernum = int(input("Usernum: "))

    # variable for testing, if True, write L2 and L3 managers output in stdout buffer
    print_output = False
    
    # try to perform database connection and country check
    try:
        # with base handler class, check payment to decide country user or not
        country, db_manager, record_data, inactive_payment = DiagHandler.decide_country_or_city(usernum)

        # base annotation for handler object
        handler: DiagHandler

        # depending on country or not, create main handler object
        if country:
            handler = CountryDiagHandler(usernum, db_manager, record_data, inactive_payment, print_output)
        else:
            handler = CityDiagHandler(usernum, db_manager, record_data, inactive_payment, print_output)
        
        # delete this function's database manager reference so class instance could control it
        del db_manager

        # run diagnostics
        handler.check_all()

    # exception in this function, print traceback
    except Exception:
        print("Exception while working with the database record:")
        traceback.print_exc()
    
if __name__ == "__main__":
    start_time = time.perf_counter()
    main()
    print(time.perf_counter() - start_time)

    # test_db_manager = TestDatabaseManager()

    # for usernum in test_db_manager.get_random_usernums():
    #     print(usernum)
    #     start_time = time.perf_counter()
    #     main(usernum)
    #     print(time.perf_counter() - start_time)
