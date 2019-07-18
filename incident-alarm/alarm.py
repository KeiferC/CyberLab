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
#       usage:          alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]
#
#       TODO : Change '%' to .format for deprecation reasons
#

from scapy.all import *
import pcapy
import argparse
import base64
import sys
import re

#########################################
# Main                                  #
#########################################
incidents_log = {}
incident_counter = 0

def main():
        parse_args()
        sys.exit()

#########################################
# Vuln detection functions              #
#########################################
# packet_callback
#       
# Callback function for sniff function. Checks for insecure protocols
# (HTTP and FTP) and stealth scans (NULL, FIN, and XMAS)
#
# @param        PacketList packet
# @returns      n/a
def packet_callback(packet):
        try:
                if (TCP in packet):
                        if packet[TCP].dport == 80 or \
                           packet[TCP].dport == 21:
                                check_for_payload(packet, packet[TCP].dport)

                        check_tcp_flags(packet, str(packet[TCP].flags))

        except Exception as e:
                print("Error: Unable to read packet.", e)

# Plaintext Vulns =======================
# check_for_payload
#       
# Callback function for sniff function. Checks for insecure protocols
# (HTTP and FTP) and stealth scans (NULL, FIN, and XMAS)
#
# @param        PacketList packet
# @param        int port
# @returns      n/a
def check_for_payload(packet, port):
        try:
                if packet[TCP].payload:
                        payload = str(packet[TCP].payload.load)
                        grab_pass(packet, payload, port)

        except Exception as e:
                print("Error: Unable to read payload.", e)

# grab_pass
#       
# Helper function to direct port-specific password
# parsing
#
# @param        PacketList packet
# @param        string payload
# @param        int port
# @returns      n/a
def grab_pass(packet, payload, port):
        try:
                user = None
                passwd = None
                incident_type = "plaintext"

                if port == 80:
                        grab_pass_http(packet, payload)
                elif port == 21:
                        grab_pass_ftp(packet, payload)

        except Exception as e:
                print("Error: Unable to read port.", e)

# grab_pass_http
#       
# Parses HTTP payload for usernames and passwords 
# and sends them to be logged
#
# @param        PacketList packet
# @param        string payload
# @returns      n/a
def grab_pass_http(packet, payload):
        try:
                user = None
                passwd = None
                incident_type = "plaintext"
                userpass = None

                if "Authorization: Basic" in payload:
                        userpass_regex = re.compile(r'''(
                                (Authorization:\sBasic\s)
                                ((.*?)\\r\\n))''', re.VERBOSE)

                        userpass = userpass_regex.search(payload)

                        if userpass:
                                userpass = parse_userpass(userpass)
                                user  = get_http_user(userpass)
                                passwd = get_http_pass(userpass)
                                log(packet, incident_type, user, passwd, None)

        except Exception as e:
                print("Error: Unable to parse HTTP payload.", e)

# grab_pass_ftp
#       
# Parses FTP payload for usernames and passwords 
# and sends them to be logged
#
# @param        PacketList packet
# @param        string payload
# @returns      n/a
def grab_pass_ftp(packet, payload):
        try:
                user = None
                passwd = None
                incident_type = "plaintext"

                if "USER" in payload:
                        user = payload.lstrip("b'USER ")
                        user = user.rstrip("\\r\\n'")
                        log(packet, incident_type, user, passwd, None)
                elif "PASS" in payload:
                        passwd = payload.lstrip("b'PASS ")
                        passwd= passwd.rstrip("\\r\\n'")
                        log(packet, incident_type, user, passwd, None)

        except Exception as e:
                print("Error: Unable to parse FTP payload.", e)

# parse_userpass
#       
# Parses retrieved regex match and returns
# a plaintext string containing the username:
# password pair
#
# @param        SRE_Match userpass
# @returns      string
def parse_userpass(userpass):
        userpass = userpass.group(1)
        userpass = userpass.lstrip("Authorization: Basic ")
        userpass = userpass.rstrip("\\r\\n")
        userpass = base64.b64decode(userpass)
        return str(userpass)

# get_http_user
#       
# Returns string username from userpass
#
# @param        string userpass
# @returns      string
def get_http_user(userpass):
        user_regex = re.compile(r"b'(.*?)\:", re.VERBOSE)
        user = user_regex.search(userpass)

        if user:
                user = str(user.group(1))
                return user
        else:
                raise Exception("Unable to retrieve username from HTTP")

# get_http_user
#       
# Returns string username from userpass
#
# @param        string userpass
# @returns      string
def get_http_pass(userpass):
        pass_regex = re.compile(r"\:(.*?)'")
        passwd = pass_regex.search(userpass)

        if passwd:
                passwd = str(passwd.group(1))
                return passwd
        else:
                raise Exception("Unable to retrieve password from HTTP")

# Stealth Scan Detection ================
# check_tcp_flags
#
# Sends FIN, NULL, and XMAS scans to log
#
# @param        PacketList packet
# @param        string flags
# @returns      n/a
def check_tcp_flags(packet, flags):
        incident_type = "scan"
        scan_type = None

        if not flags:
                scan_type = "Null scan"
        elif str(flags) == "F":
                scan_type = "Fin scan"
        elif str(flags) == "FPU":
                scan_type = "Xmas scan"
        else:
                return
        
        log(packet, incident_type, None, None, scan_type)
        
#########################################
# Incident logging functions            #
#########################################
# log
#       
# Logs incident
#
# @param        PacketList packet
# @param        string incident_type
# @param        string user
# @param        string passwd
# @param        string scan_type
# @returns      n/a
def log(packet, incident_type, user, passwd, scan_type):
        ip = packet[IP].src

        if ip not in incidents_log:
                incidents_log[ip] = new_incident(incident_type, user, passwd)

        incident = incidents_log[ip]
                
        if incident_type == "plaintext":
                log_plaintext(packet, incident, user, passwd)
        elif incident_type == "scan":
                log_scan(packet, incident, scan_type)

# log_plaintext
#       
# Logs plaintext-specific incident
#
# @param        PacketList packet
# @param        dict incident
# @param        string user
# @param        string passwd
# @returns      n/a
def log_plaintext(packet, incident, user, passwd):
        if incident["proto"] == None:
                incident["proto"] = packet[TCP].dport
        if user != None:
                incident["user"] = user
        if passwd != None:
                incident["pass"] = passwd
        if incident["user"] != None and incident["pass"] != None:
                print_incident(packet[IP].src)

# log_scan
#       
# Logs plaintext-specific incident
#
# @param        PacketList packet
# @param        dict incident
# @param        string scan_type
# @returns      n/a
def log_scan(packet, incident, scan_type):
        incident["proto"] = packet[IP].proto
        incident["scan_type"] = scan_type
        print_incident(packet[IP].src)

# new_incident
#
# Returns an incident log object with some
# initialized keys
#
# @param        string incident_type
# @param        string user
# @param        string passwd
# @returns      dict
def new_incident(incident_type, user, passwd):
        incident = {
                "incident_type": incident_type,
                "user": user,
                "pass": passwd,
                "scan_type": None,
                "proto": None
        }
        return incident

#########################################
# Printing functions                    #
#########################################
# print_incidents
#
# prints all logged incidents
#
# @param        string incident
# @returns      n/a
def print_incident(incident):
        global incident_counter
        incident_counter += 1
        details = incidents_log[incident]
        payload = None
        output = "Alert #{0}: ".format(incident_counter)

        if details["incident_type"] == "plaintext":
                payload = "(username:{0}, password:{1})".format(
                           details["user"], details["pass"])
                output += format_plaintext_output(incident, details)
        elif details["incident_type"] == "scan":
                output += format_scan_output(incident, details)
        
        output += "({0})".format(details["proto"])

        if payload != None:
                output  += " {0}".format(payload)
        
        output += "!"

        print(output)

# format_plaintext_output
#
# Formats plaintext-specific output
#
# @param        string incident
# @param        dict details
# @returns      string
def format_plaintext_output(incident, details):
        output = "Usernames and passwords sent in-the-clear "
        output += "from {0} ".format(incident)
        details["user"] = None
        details["pass"] = None
        return output

# format_scan_output
#
# Formats scan-specific output
#
# @param        string incident
# @param        dict details
# @returns      string
def format_scan_output(incident, details):
        return "{0} is detected from {1} ".format(details["scan_type"], 
                                                  incident)

#########################################
# Command-line Interface                #
#########################################
# set_parser_args
#       
# Sets up parser command-line arguments
#
# @param        n/a
# @returns      argument parser
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

# parse_args
#       
# Parses command-line arguments
#
# @param        n/a
# @returns      n/a
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
