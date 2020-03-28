#!/usr/bin/python3

#
#       filename:       collator.py
#       author:         @KeiferC
#       date:           23 July 2019
#       version:        0.0.1
#       
#       description:    Recursively collects all .txt entries in a
#                       directory and prints to output
#
#       usage:          collator.py <SECLIST_DIRECTORY>
#
#       TODO:           documentation
#                       sorting options
#

from difflib import SequenceMatcher
import requests
import random
import math
import glob
import sys
import os

#########################################
# Main                                  #
#########################################
def main():
        directory = None
        payloads = None

        try:
                directory = get_dir()
        except ValueError as e:
                print("Error:", e)
                sys.exit()
        
        try:
                payloads = get_payloads(directory)
        except Exception as e:
                print("Error:", e)
                sys.exit()
        
        for word in payloads:
                print(word)


#########################################
# Functions                             #
#########################################
def get_payloads(directory):
        payloads = []

        for filename in glob.glob(os.path.join(directory, 
                                  "**/*.txt"), recursive = True):
                file = open(filename, "r", encoding = "latin-1")

                for line in file:
                        payloads.append(line.rstrip('\n'))
        
        payloads = list(set(payloads))

        if len(payloads) == 0:
                raise Exception("No .txt files found in given directory.")

        return payloads


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
                '''Usage:       collator.py <SECLIST_DIRECTORY>
                         <SECLIST_DIRECTORY>: Path to seclist directory'''
             )

#########################################
# Function Calls                        #
#########################################
main()
