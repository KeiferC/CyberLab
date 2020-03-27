#
#       filename:       crack-jwt.py
#       author:         @KeiferC
#       date:           27 Mar 2019
#       version:        0.0.1
#       
#       description:    Quick script crack JWT secret encrypted
#                       with HMACSHA256
#
#       usage: crack-jwt.py [-h] <FILE> <TOKEN>
#

import sys, argparse

#########################################
# Main                                  #
#########################################
# 
# Validates input, parses command-line arguments, runs program.
#
# @param        n/a
# @returns      n/a
#
def main():
        args            = parse_arguments()
        filename        = args["filename"]
        token           = args["token"]
        wordslist       = parse_infile(filename)
        secrets_list    = crack_token(token, wordslist)

        print("{0} successes out of {1} attempts.".format(
                len(secrets_list), len(wordlist)))
        
        if secrets_list:
                print("Success(es):")
                print(secrets_list)

        sys.exit()


#########################################
# Functions                             #
#########################################
#
# Given a JWT with a secret encrypted with HMACSHA256 and a array
# of words, returns a list of found secrets
#
# @param        {str} token: JWT token to crack
# @param        {list} wordslist: wordslist words
# @returns      {list} list of found secrets
#
def crack_token(token, wordslist):
        return wordslist # TODO


#########################################
# Command-Line Parsing                  #
#########################################
#
# Parses command-line arguments and returns a dictionary of argument
# objects
#
# @param        n/a
# @returns      {dictionary} Contains following key-value pairs:
#                       {str} filename: name of file to parse
#                       {str} token: JWT to crack
#
def parse_arguments():
        description     = "Cracks given JWT HMACSHA256 secret."
        file_help       = "name of wordlist file"
        token_help      = "JWT to crack"
        parser          = argparse.ArgumentParser(description=description)

        parser.add_argument("filename", metavar="<FILE>", help=file_help)
        parser.add_argument("token", metavar="<TOKEN>", type=str, 
                            help=token_help)

        return vars(parser.parse_args())

#
# Given a wordlist filename, returns an list of words from file
#
# @param        {str} filename: wordslist file to open
# @returns      {list} list of words from wordslist
#
def parse_infile(filename):
        wordlist = ""

        try:
                with open(filename, 'r') as file:
                        for line in file:
                                for word in line.split():
                                        wordlist.append(word)
        except FileNotFoundError:
                print("No such file \'{}\' in directory.".format(filename))
                sys.exit("Error: FileNotFoundError.")
        except:
                print("Unable to open file \'{}\'.".format(filename))
                sys.exit("Error: Unable to open file.")

        return wordlist


#########################################
# Function Calls                        #
#########################################
if __name__ == "__main__":
        main()
