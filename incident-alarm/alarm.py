#!/usr/bin/python3

#
#       filename:       alarm.py
#       author:         @KeiferC
#       date:           17 July 2019
#       version:        0.0.1
#       
#       description:    Alerts user when somthing shady is going
#                       on in the network
#
#       references:     
#          - https://0xbharath.github.io/art-of-packet-crafting-with-scapy/
#
#       usage:          python alarm.py ...
#

from scapy.all import *
import pcapy
import argparse
import sys

#########################################
# Main                                  #
#########################################
incidents_log = {}

def main():
        parse_args()
        print_incidents()
        sys.exit()

#########################################
# Vuln detection functions              #
#########################################
#
# packet_callback
#       
# Callback function for sniff function. Checks for insecure protocols
# (HTTP and FTP) and stealth scans (NULL, FIN, and XMAS)
#
# @param        packet object
# @return       n/a
#
def packet_callback(packet):
        try:
                if (packet[TCP].dport == 80 or packet[TCP].dport == 21):
                        check_for_payload(packet, packet[TCP].dport)
        except:
                print("Error: Unable to read packet.")

#
# check_for_payload
#       
# Callback function for sniff function. Checks for insecure protocols
# (HTTP and FTP) and stealth scans (NULL, FIN, and XMAS)
#
# @param        packet object
# @param        int port
# @return       n/a
#
def check_for_payload(packet, port):
        try:
                userpass = None;

                if packet[TCP].payload:
                        payload = str(packet[TCP].payload.load)
                        grab_pass(packet, payload, port)
        except:
                print("Error: Unable to read payload")

#
# grab_pass
#       
# Given payload and port, looks for username:password 
# pairs and returns them if exists
#
# @param        packet
# @param        string payload
# @param        int port
# @return       n/a
#
def grab_pass(packet, payload, port):
        try:
                user = None
                passwd = None
                incident_type = "plaintext"

                if port == 80:
                        print("http")
                elif port == 21:
                        if "USER" in payload:
                                user = payload.lstrip("b'USER ")
                                user = user.rstrip("\\r\\n'")
                                log(packet, incident_type, user, passwd, None)
                        elif "PASS" in payload:
                                passwd = payload.lstrip("b'PASS ")
                                passwd= passwd.rstrip("\\r\\n'")
                                log(packet, incident_type, user, passwd, None)
        except:
                print("Error: Unable to parse payload string")

#########################################
# Incident logging functions            #
#########################################
#
# log
#       
# Logs incident
#
# @param        packet
# @param        string payload
# @param        int port
# @return       n/a
#
def log(packet, incident_type, user, passwd, scan_type):
        src_ip = packet[IP].src

        if src_ip not in incidents_log:
                incidents_log[src_ip] = {
                        "incident_type": incident_type,
                        "user": user,
                        "pass": passwd,
                        "scan_type": None,
                        "proto": None
                }

        incident = incidents_log[src_ip]
                
        if incident_type == "plaintext":
                if incident["proto"] == None:
                        incident["proto"] = packet[TCP].dport
                if user != None:
                        incident["user"] = user
                if passwd != None:
                        incident["pass"] = passwd

        elif incident_type == "scan":
                incident["proto"] = packet[IP].proto
                incident["scan_type"] = scan_type

#
# print_incidents
#
# prints all logged incidents
#
# @param        n/a
# @returns      n/a
#
def print_incidents():
        incident_counter = 0;

        for incident, details in incidents_log.items():
                incident_counter += 1
                payload = None
                output = "Alert #{0}: ".format(incident_counter)

                if details["incident_type"] == "plaintext":
                        payload = "(username:{0}, password:{1})".format(
                                details["user"], 
                                details["pass"])
                        output += "Usernames and passwords sent in-the-clear "
                        output += "from {0} ".format(incident)

                elif details["incident_type"] == "scan":
                        output += "{0} is detected from {1} ".format(
                                details["scan_type"], 
                                incident)
                
                output += "({0})".format(details["proto"])

                if payload != None:
                        output  += " {0}".format(payload)
                
                output += "!"

                print(output)

#########################################
# Command-line Interface                #
#########################################
#
# set_parser_args
#       
# Sets up parser command-line arguments
#
# @param        n/a
# @return       argument parser
#
def set_parser_args():
        parser = argparse.ArgumentParser(
                description='A network sniffer that identifies basic \
                             vulnerabilities')

        parser.add_argument(
                '-i', 
                dest='interface', 
                help='Network interface to sniff on', 
                default='eth0')

        parser.add_argument(
                '-r', 
                dest='pcapfile', 
                help='A PCAP file to read')

        return parser.parse_args()

#
# parse_args
#       
# Parses command-line arguments
#
# @param        n/a
# @return       n/a
#
def parse_args():
        args = set_parser_args()

        if args.pcapfile: # Reading from pcap file
                try:
                        print("Reading PCAP file %(filename)s..." % 
                              {"filename" : args.pcapfile})
                        sniff(offline=args.pcapfile, prn=packet_callback)  
                except:
                        print("Sorry, something went wrong reading PCAP \
                              file %(filename)s!" %
                              {"filename" : args.pcapfile})

        else: # Sniffing on interface
                print("Sniffing on %(interface)s... " % 
                      {"interface" : args.interface})
                try:
                        sniff(iface=args.interface, prn=packet_callback)
                except pcapy.PcapError:
                        print("Sorry, error opening network interface \
                              %(interface)s. It does not exist." % 
                              {"interface" : args.interface})
                except:
                        print("Sorry, can\'t read network traffic. \
                              Are you root?")

#########################################
# Function Calls                        #
#########################################
main()
