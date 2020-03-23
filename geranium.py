#!/usr/local/bin/python3

import yaml

import data_generation
import data_processing

import sys, getopt

# Do This https://docs.python.org/dev/library/argparse.html#sub-commands

def get_config():
    # Open the config file and return it if 
    # its found
    with open("config.yaml", 'r') as stream:
        try:
            return(yaml.safe_load(stream))
        except yaml.YAMLError as exc:
            print(exc)

def main(argv):
    config = get_config()
    try:
        opts, args = getopt.getopt(argv,"h",["generate","process","model"])
    except getopt.GetoptError:
        print ('Usage: geranium.py <command> [args]')
        print ('Available commands are:')
        print ('   generate    Generate the data from virtual machines')
        print ('   process     Process data which has been generated')
        print ('   model       Build a decision tree model')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('Usage: geranium.py <command> [args]')
            print ('Available commands are:')
            print ('   generate    Generate the data from virtual machines')
            print ('   process     Process data which has been generated')
            print ('   model       Build a decision tree model')
            sys.exit()
        if opt == 'generate':
            print ('generate')
        elif opt == "process":
            print ('process')
        elif opt == "model":
            print ('model')

        

if __name__ == "__main__":
   main(sys.argv[1:])

