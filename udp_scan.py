# coding: utf8
import threading
import time
import socket
import os
import utils
import struct
#from netaddr import IPNetwork, IPAddress
import ctypes

class ICMP(ctypes.Structure):
    _fields_ = [
        ('type',        ctypes.c_ubyte),
        ('code',        ctypes.c_ubyte),
        ('checksum',    ctypes.c_ushort),
        ('unused',      ctypes.c_ushort),
        ('next_hop_mtu',ctypes.c_ushort)
    ]
        
    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
               
    def __init__(self, socket_buffer):
        pass

# 主机监听的端口
HOST = '192.168.1.114'
# subnet to target (iterates through all IP address in this subnet)
SUBNET = '192.168.1.0/24'
# 数字签名
MESSAGE = 'hellooooo'

# 发送 udp 数据包
def udp_sender(SUBNET, MESSAGE):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in IPNetwork(SUBNET):
        try:
            sender.sendto(MESSAGE, ("%s" % ip, 65212))
        except:
            pass

def main():
    t = threading.Thread(target=udp_sender, args=(SUBNET, MESSAGE))
    t.start()
            
    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind(( HOST, 0 ))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                 
    # 持续接收消息包并且解析消息
    while 1:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = raw_buffer[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
                                                                
        # 创建 IP 结构
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        src_addr = socket.inet_ntoa(iph[8]);
                                                                                         
        # 创建 ICMP 结构
        buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)
                                                                  
        # 检验 type 3
        if icmp_header.code == 3 and icmp_header.type == 3:
            if IPAddress(src_addr) in IPNetwork(SUBNET):
                if raw_buffer[len(raw_buffer) - len(MESSAGE):] == MESSAGE:
                    print("Host up: %s" % src_addr)

def udp_scan(ip, port):
    utils.udp_scan(ip, port)
