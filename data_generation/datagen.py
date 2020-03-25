import os
import threading
import sys, getopt
import argparse
import urllib.request
import time
from packerpy import PackerExecutable

import sys
sys.path.append('..')
import data_processing


class DataGen():

    def __init__(self, 
                attack, 
                attack_path,
                executable_path, 
                time, 
                attack_machine_path, 
                target_machine_path, 
                attack_username, 
                attack_password, 
                attack_ip,
                dataset_path):

        print("#######################")
        print("#   DATA GENERATION   #")
        print("#######################")
        print ('\n')
        
        self.attack = attack
        self.attack_path = attack_path
        self.executable_path = executable_path
        self.time = time
        self.attack_machine_path = attack_machine_path
        self.target_machine_path = target_machine_path
        self.attack_username = attack_username 
        self.attack_password = attack_password
        self.attack_ip = attack_ip
        self.dataset_path = dataset_path
        #Check the arguments and run the relevent vms

        if self.attack == "normal":
            print("--------------------------------------------------------------")
            print("Normal Network Data Generation" )
            print("--------------------------------------------------------------")
            #start collecting network data
            capture = threading.Thread(target = self.snif_packets)
            capture.start()

            # Start Generating Normal Network Data using 
            # https://github.com/ecapuano/web-traffic-generator
            os.system("timeout " + str(self.time) + " python3 data_generation/traffic-gen/gen.py")
            
        else:
            # Run the virtual machines
            print("--------------------------------------------------------------")
            print("Run Virtual Machines")
            print("--------------------------------------------------------------")
            self.run_vms()

            # Start collecting network data if the machine is up
            up = False
            while (not up):
                up = self.ping_vm()
            
            time.sleep(10)
            #start collecting network data
            print("Start Collecting Network Data")
            print("--------------------------------------------------------------")
            capture = threading.Thread(target = self.snif_packets)
            capture.start()

    # Runs an 7 machine and an attack machine to run exploits within it.
    def run_vms(self):
        #Create the attack machine in a seperate thread
        att = threading.Thread(target = self.create_attack_machine)
        att.start()

        #Create the other target machine in a seperate thread
        m1 = threading.Thread(target = self.create_network_target)
        m1.start()

    def ping_vm(self):
        response = os.system("ping -c 1 " + self.attack_ip + " 2>&1 >/dev/null")

        # Check if the machine is up
        if response == 0:
            return True
        else:
            return False

    #Run scapy and collect the network packets
    def snif_packets(self):
        parser = data_processing.DataParser(self.attack, self.dataset_path, self.time)
        parser.sniff_packets()
        parser.collate_packets()


    #Function which runs the attack machine packer build
    def create_attack_machine(self):
        print("Building the attack machine: " + self.attack_machine_path + "\n""--------------------------------------------------------------")
        p = PackerExecutable(self.executable_path)
        # Build the attack template
        attack_template = """{{
            "builders": [
                {{
                "type"                  : "virtualbox-ovf",
                "vboxmanage"            : [
                                            ["modifyvm", "attack", "--bridgeadapter1", "en0"]
                                          ],
                "source_path"           : "{machine}",
                "vm_name"               : "attack",
                "boot_wait"             : "30s",
                "ssh_host"              : "{ip}",
                "ssh_port"              : 22,
                "ssh_username"          : "{username}",
                "ssh_timeout"           : "20m",
                "ssh_password"          : "{password}",
                "ssh_skip_nat_mapping"  : "true"
                }}
            ],
            "provisioners":
            [
                {{
                "type": "shell",
                "script": "{attack}"
                }}
            ]
        }}
        """
        # Build the template
        template = attack_template.format(attack = self.attack_path, 
                                          machine = self.attack_machine_path, 
                                          ip = self.attack_ip,
                                          username = self.attack_username,
                                          password = self.attack_password)
        (_, out, err) = p.build(template, force=True)
        print (out)
        if err:
            print (err)

    #Function which runs the network target machine build
    def create_network_target(self):
        print("Building the target machine: " + self.target_machine_path + "\n""--------------------------------------------------------------")
        p = PackerExecutable(self.executable_path)
        target_time = 300 + self.time
        template = """{{
            "builders": [
                {{
                "type"                  : "virtualbox-ovf",
                "vboxmanage"            : [
                                            ["modifyvm", "target", "--bridgeadapter1", "en0"]
                                          ],
                "source_path"           : "{machine}",
                "vm_name"               : "target",
                "communicator"          : "none",
                "boot_wait"             : "{time}s"
                }}
            ]
        }}
        """
        # Build the template
        template = template.format(machine = self.target_machine_path, time = target_time)
        (_, out, err) = p.build(template, force=True)
        print (out)
        if err:
            print (err)

