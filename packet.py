#!/usr/bin/python3
import sys
# user's modules
from main_handler import MainHandler


##### START SCANNING #####

def main():
    # get usernum from argument string, first element of argv is file's name
    if len(sys.argv) >= 2:
        usernum = int(sys.argv[1])
    # or from input
    else:
        usernum = int(input("Usernum: "))
    
    # create handler object and run diagnostics
    handler = MainHandler(usernum)
    handler.check_packet()

if __name__ == "__main__":
    main()