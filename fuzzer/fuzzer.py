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
        input_list = None
        respones = None

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

        try:
                responses = fuzz(input_list)
        except Exception as e:
                print("Error:", e)
                sys.exit()
        
        calc_risk(responses)
        
#########################################
# Functions                             #
#########################################

# Algorithm
#       Split array into two. compare each elem to corresponding
#       store all ratios into array
#       find mode == average difference --> implied normal response
#       count number of ratios < mode (not similar to normal response)
#       print number as possible successful injections
def calc_risk(responses):
        ratios = []
        mode = None
        risk_counter = 0
        midpoint = math.floor(len(responses) / 2)
        j = 0

        random.shuffle(responses)

        for i in range(0, midpoint):
                ratios.append(SequenceMatcher(None, responses[i], 
                                              responses[midpoint + i]).ratio())
        
        mode = max(set(ratios), key = ratios.count)
        ratios.sort()

        while j < len(ratios) and ratios[j] < mode:
                risk_counter += 1
                j += 1

        print("Avg similarity ratio of HTTP responses:", mode)
        print("Number of delivered payloads:", len(responses))
        print("Number of potential successful XSS attacks:", risk_counter)
        print("Percent success of XSS attacks: {:.3%}".format(risk_counter / 
              len(responses)))


def fuzz(input_list):
        url = "http://www.cs.tufts.edu/comp/20/hackme.php"
        data = {
                "price": None,
                "fullname": None,
                "beverage": None,
                "submitBtn": None
        }
        response_list = []

        for payload in input_list:
                for key in data:
                        data[key] = payload
                
                response = requests.post(url, data)
                response_list.append(response.text)
        
        if len(response_list) == 0:
                raise Exception("Unable to POST to URL.")
        
        return response_list


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
