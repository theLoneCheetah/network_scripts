#!/usr/bin/python3
# user's modules
from main_handler import MainHandler


##### START DIAGNOSTICS #####

def main():
    # get usernum
    usernum = int(input("Usernum: "))
    
    # create handler object and run diagnostics
    handler = MainHandler(usernum)
    handler.check_all()

if __name__ == "__main__":
    main()
