#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import time
import utils
from socket import *

def scan_start():
    # port_scan.py <host> <start_port>-<end_port>
    host = sys.argv[1]
    portstrs = sys.argv[2].split('-')
    
    start_port = int(portstrs[0])
    end_port = int(portstrs[1])
    
    target_ip = gethostbyname(host)
    opened_ports = []

    for port in range(start_port, end_port):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(100)
        result = sock.connect_ex((target_ip, port))
        print result
        if result == 0:
            print '端口开放:' + str(port) 
            opened_ports.append(port)
        else:
            print '端口关闭:' + str(port) 
    
def tcp_connect_scan(ip, port):
    utils.tcp_connect_scan(ip, port)
