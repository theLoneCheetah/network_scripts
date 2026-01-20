#!/usr/bin/python3
import traceback
# user's modules
from diag_handler import DiagHandler
from city_diag_handler import CityDiagHandler
from country_diag_handler import CountryDiagHandler


##### START DIAGNOSTICS #####

def main() -> None:
    # get usernum
    usernum = int(input("Usernum: "))

    # variable for testing, if True, write L2 and L3 managers output in stdout buffer
    print_output = False
    
    # try to perform database connection and country check
    try:
        # with base handler class, check payment to decide country user or not
        country, db_manager, record_data, inactive_payment = DiagHandler.decide_country_or_city(usernum)

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
    except Exception as err:
        print("Exception while working with the database record:")
        traceback.print_exc()
    
if __name__ == "__main__":
    main()
