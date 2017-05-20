# coding: utf8

import arp_scan
import icmp_scan
import tcp_connect_scan
import tcp_fin_scan
import tcp_syn_scan
import udp_scan
import os

mp = {
    1: arp_scan.arp_scan,
    2: icmp_scan.icmp_scan,
    3: tcp_connect_scan.tcp_connect_scan,
    4: tcp_fin_scan.tcp_fin_scan,
    5: tcp_syn_scan.tcp_syn_scan,
    6: udp_scan.udp_scan
}

def start():
    print '======端口扫描程序======'
    print '1.ARP 主机探测'
    print '2.ICMP 主机探测'
    print '3.TCP Connect 扫描'
    print '4.TCP FIN 扫描'
    print '5.TCP SYN 扫描'
    print '6.UDP 扫描'
    print '========================'
    print '\n\n\n请选择：'
    select = int(raw_input())
    os.system('clear')
    if select == 1:
        ip = raw_input('请输入 IP 地址:')
        mp[select](ip)
    elif select == 2:
        ip = raw_input('请输入 IP 地址范围:')
        mp[select](ip)
    elif select == 3:
        ip = raw_input('请输入 IP 地址(如:www.baidu.com)):')
        port = raw_input('请输入端口或端口范围:')
        mp[select](ip, port)
    elif select == 4:
        ip = raw_input('请输入 IP 地址(如:www.baidu.com)):')
        port = raw_input('请输入端口或端口范围:')
        mp[select](ip, port)
    elif select == 5:
        ip = raw_input('请输入 IP 地址(如:www.baidu.com)):')
        port = raw_input('请输入端口或端口范围:')
        mp[select](ip, port)
    elif select == 6:
        ip = raw_input('请输入 IP 地址(如:www.baidu.com)):')
        port = raw_input('请输入端口或端口范围:')
        mp[select](ip, port)
    else:
        print '选择错误，请重试'


if __name__ == '__main__':
    os.system('clear')
    start()
