#!/usr/bin/env python3

import sys

from common.Cruncher import *



if __name__ == "__main__":
    crunch = Cruncher()
    
    args = crunch.parse_cli_args(sys.argv[1:])
    
    crunch.run_cmd('help')
    try:
        crunch.main_menu()
    except KeyboardInterrupt:
        print("exit")
