#!/usr/local/bin/python3

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

import yaml

import data_generation
import data_processing
import data_modeling
import intrusion_detection

import sys, argparse
import os
import atexit

class Geranium(object):

    def __init__(self):
        print ('''   ____ _____ ____     _    _   _ ___ _   _ __  __ 
  / ___| ____|  _ \   / \  | \ | |_ _| | | |  \/  |
 | |  _|  _| | |_) | / _ \ |  \| || || | | | |\/| |
 | |_| | |___|  _ < / ___ \| |\  || || |_| | |  | |
  \____|_____|_| \_/_/   \_|_| \_|___|\___/|_|  |_|''')
        print("--------------------------------------------------------------")
        
        # Import the config file
        try:
            self.get_config()
        except:
            print("Error, can't import the config file")
            sys.exit(2)

        # Start the argument parsers
        parser = argparse.ArgumentParser(
            description='Program to generate, procees and model network data',
            usage='''geranium.py <command> [args]
            
Avalibile commands:
    generate     Generates network data
    clearvms     Clears previous vms         
    process      Processes network data
    model        Models network data
    ids          Runs an IDS with a model
            ''')
        parser.add_argument('command', help='Run the required commands for the program')

        # parse_args defaults to [1:] for args, but need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print ('Unrecognized command')
            parser.print_help()
            exit(1)

        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()

    def get_config(self):

        # Open the config file and return all the variables in the file
        with open("config.yaml", 'r') as stream:
            try:
                # Get the items from the config file
                config = yaml.safe_load(stream) 
                self.executable_path = config['data-generation']['executable_path']
                self.time = config['data-generation']['time']
                self.attack_machine_path = config['data-generation']['attack_machine_path']
                self.target_machine_path = config['data-generation']['target_machine_path']
                self.attack_username = config['data-generation']['attack_username']
                self.attack_password = config['data-generation']['attack_password']
                self.attack_ip = config['data-generation']['attack_ip']
                self.filter_ip = config['data-generation']['filter_ip']
                self.dataset_path = config['data-processing']['dataset_path']
                self.filter = config['data-processing']['filter']
                self.model_path = config['data-modeling']['model_path']
                self.classes = config['data-modeling']['classes']
                self.ids_model = config['ids']['model']
            except yaml.YAMLError as exc:
                print("Error:" + exc)
                sys.exit(2)

    def generate(self):

        # Start the argument parsers
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
                                    self.dataset_path,
                                    None)
            else:
                # Set the exit handler
                # Ensure on exit that the virtual machines get wiped
                atexit.register(self.exit_handler)

                # Start the data generation part of the project
                data_generation.DataGen(sys.argv[2], 
                                        sys.argv[3], 
                                        self.executable_path, 
                                        self.time, 
                                        self.attack_machine_path,
                                        self.target_machine_path,
                                        self.attack_username,
                                        self.attack_password,
                                        self.attack_ip,
                                        self.dataset_path,
                                        self.filter_ip)
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
            data_modeling.DataModeling(sys.argv[2], self.model_path, self.classes)
        except:
            parser.print_help()
    
    def ids(self):
        parser = argparse.ArgumentParser(
            description='Run an IDS with a trained model',
            usage='''geranium.py ids''')
        # Start the data processing part of the project and generate the file
        try:
            intrusion_detection.IDS(self.ids_model)
        except:
            parser.print_help()

    def clearvms(self):
        # Start the data processing part of the project and generate the file
        self.exit_handler()
    
    def exit_handler(self):
        print("Delete attack and target machines")
        print("--------------------------------------------------------------")
        # Delete the virtual machines
        os.system('VBoxManage unregistervm --delete "attack"')
        os.system('VBoxManage unregistervm --delete "target"')
        # Remove any folders created by packer
        os.system('rm -r packer_cache/')
        os.system('rm -r output-virtualbox-ovf/')

if __name__ == '__main__':
    Geranium()

