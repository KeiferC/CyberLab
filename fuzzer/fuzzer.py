#!/usr/bin/python3

#
#       filename:       fuzzer.py
#       author:         @KeiferC
#       date:           23 July 2019
#       version:        0.0.1
#       
#       description:    Fuzzes http://www.cs.tufts.edu/comp/20/hackme.php
#                       for XSS vulns
#
#       usage:          fuzzer.py <SECLIST_DIRECTORY>
#
#       Seclist:        https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
#

import requests
import glob
import sys
import os

#########################################
# Main                                  #
#########################################
def main():
        directory = None
        input_list = None

        try:
                directory = get_dir()
        except ValueError as e:
                print("Error:", e)
                sys.exit()
        
        try:
                input_list = get_input_list(directory)
        except Exception as e:
                print("Error:", e)
                sys.exit()

        fuzz(input_list)


#########################################
# Functions                             #
#########################################
def fuzz(input_list):


def get_input_list(directory):
        list = []

        for filename in glob.glob(os.path.join(directory, 
                                  "**/*.txt"), recursive = True):
                file = open(filename, "r", encoding = "latin-1")

                for line in file:
                        list.append(line.rstrip('\n'))
        
        if len(list) == 0:
                raise Exception("No .txt files found in given directory.")

        return list

#########################################
# Argument Parsing                      #
#########################################
def get_dir():
        if len(sys.argv) == 2:
                directory = sys.argv[1]
                if os.path.isdir(directory):
                        return directory
                raise ValueError("{0} is not a valid directory.".format(directory))
        else:
                usage()
                sys.exit()

def usage():
        print(
                '''Usage:  fuzzer.py <SECLIST_DIRECTORY>
                  <SECLIST_DIRECTORY>: Path to seclist directory'''
             )

#########################################
# Function Calls                        #
#########################################
main()
