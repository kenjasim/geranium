#!/usr/local/bin/python3

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

import yaml

import data_generation
import data_processing
import data_modeling
import intrusion_detection

import sys, argparse
import atexit

# Do This https://docs.python.org/dev/library/argparse.html#sub-commands

class Geranium(object):

    def __init__(self):
        print ('''   ____ _____ ____     _    _   _ ___ _   _ __  __ 
  / ___| ____|  _ \   / \  | \ | |_ _| | | |  \/  |
 | |  _|  _| | |_) | / _ \ |  \| || || | | | |\/| |
 | |_| | |___|  _ < / ___ \| |\  || || |_| | |  | |
  \____|_____|_| \_/_/   \_|_| \_|___|\___/|_|  |_|''')
        print("--------------------------------------------------------------")
        print("Importing Config File")
        print("--------------------------------------------------------------")
        self.get_config()
        parser = argparse.ArgumentParser(
            description='Program to generate, procees and model network data',
            usage='''geranium.py <command> [args]
            
Avalibile commands:
    generate     Generates network data
    process      Processes network data
    model        Models network data
    ids          Runs an IDS with a model
            ''')
        parser.add_argument('command', help='Run the required commands for the program')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print ('Unrecognized command')
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()

    def get_config(self):
        # Open the config file and return it if 
        # its found
        with open("config.yaml", 'r') as stream:
            try:
                # Get the items from the config file
                config = yaml.safe_load(stream) 
                self.executable_path = config['data-gen']['executable_path']
                self.time = config['data-gen']['time']
                self.attack_machine_path = config['data-gen']['attack_machine_path']
                self.target_machine_path = config['data-gen']['target_machine_path']
                self.attack_username = config['data-gen']['attack_username']
                self.attack_password = config['data-gen']['attack_password']
                self.attack_ip = config['data-gen']['attack_ip']
                self.dataset_path = config['data-processing']['dataset_path']
                self.filter = config['data-processing']['filter']
                self.model_path = config['data-modeling']['model_path']
                self.image_path = config['data-modeling']['image_path']
                self.ids_model = config['ids']['model']
            except yaml.YAMLError as exc:
                print("Error:" + exc)
                sys.exit(2)

    def generate(self):
        parser = argparse.ArgumentParser(
            description='Generate network data using a VM image',
            usage='''geranium.py generate <attack name> <attack script>''')
        try:
            # Start the data generation part of the project
            if sys.argv[2] == "normal":
                data_generation.DataGen(sys.argv[2], 
                                    None, 
                                    self.executable_path, 
                                    self.time, 
                                    self.attack_machine_path,
                                    self.target_machine_path,
                                    self.attack_username,
                                    self.attack_password,
                                    self.attack_ip,
                                    self.dataset_path)
            else:
                d = data_generation.DataGen(sys.argv[2], 
                                            sys.argv[3], 
                                            self.executable_path, 
                                            self.time, 
                                            self.attack_machine_path,
                                            self.target_machine_path,
                                            self.attack_username,
                                            self.attack_password,
                                            self.attack_ip,
                                            self.dataset_path)
                # Ensure on exit that the virtual machines get wiped
                atexit.register(d.exit_handler)
        except:
            parser.print_help()


    def process(self):
        parser = argparse.ArgumentParser(
            description='Process network data into format to be modeled',
            usage='''geranium.py process <target> <network_data>''')
        # Start the data processing part of the project and generate the file
        try:
            d = data_processing.DataProcessor(sys.argv[2], sys.argv[3], self.dataset_path, self.filter)
            d.read_packets()
        except:
            parser.print_help()
    
    def model(self):
        parser = argparse.ArgumentParser(
            description='Build a decision tree model from a dataset',
            usage='''geranium.py model <dataset>''')
        try:
            # Start the data processing part of the project
            data_modeling.DataModeling(sys.argv[2], self.model_path, self.image_path)
        except:
            parser.print_help()
    
    def ids(self):
        parser = argparse.ArgumentParser(
            description='Run an IDS with a trained model',
            usage='''geranium.py ids''')
        # Start the data processing part of the project and generate the file
        try:
            i = intrusion_detection.IDS(self.ids_model)
        except:
            parser.print_help()

if __name__ == '__main__':
    Geranium()

