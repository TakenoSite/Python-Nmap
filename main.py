##!/usr/bin/env python3

from src import Nmap


"""
Thread(
    
    IP:str,       # Target host in list only
    ARGS:str,     # Nmap option
    ThreadNum:int # Thread Select
    TimeOut:int   # TimeOut Count
):

"""

Nmap.Thread(IP=[{scan_host}], ARGS={options}, ThreadNum={thread})
