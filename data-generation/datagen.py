import os
import threading
import sys, getopt
import argparse
import urllib.request
import time
from packerpy import PackerExecutable

class DataGen():

    def __init__(self, attack):
        self.attack = attack
        #Check the arguments and run the relevent vms

        if self.attack == "normal":
            #start collecting network data
            capture = threading.Thread(target = self.start_network_capture)
            capture.start()

            # Start Generating Normal Network Data using 
            # https://github.com/ecapuano/web-traffic-generator
            os.system("timeout 10m python3 traffic-gen/gen.py")
            
        else:
            # Run the virtual machines
            self.run_vms()

            # Start collecting network data if the machine is up
            up = False
            while (not up):
                up = self.ping_vm()
            
            time.sleep(10)
            #start collecting network data
            capture = threading.Thread(target = self.start_network_capture)
            capture.start()

    # Runs an 7 machine and an attack machine to run exploits within xp.
    def run_vms(self):
        #Create the attack machine in a seperate thread
        att = threading.Thread(target = self.create_attack_machine)
        att.start()

        #Create the other target machine in a seperate thread
        m1 = threading.Thread(target = self.create_network_target)
        m1.start()

    def ping_vm(self):
        response = os.system("ping -c 1 192.168.0.14 2>&1 >/dev/null")

        # Check if the machine is up
        if response == 0:
            return True
        else:
            return False

    # Run wireshark and store the file in the data folder
    def start_network_capture(self):
        command = "wireshark -k -i wlp3s0 -a duration:600 -w capture/" + self.attack + ".pcapng"
        os.system(command)
    
    #Function which runs the attack machine packer build
    def create_attack_machine(self):
        print("Building the attack machine =========================================")
        p = PackerExecutable("/usr/bin/packer")
        # Build the attack template
        attack_template = """{{
            "builders": [
                {{
                "type"                  : "virtualbox-ovf",
                "source_path"           : "virtual-machines/attack.ova",
                "vm_name"               : "attack",
                "boot_wait"             : "30s",
                "ssh_host"              : "192.168.0.14",
                "ssh_port"              : 22,
                "ssh_username"          : "root",
                "ssh_timeout"           : "20m",
                "ssh_password"          : "yeet",
                "ssh_skip_nat_mapping"  : "true"
                }}
            ],
            "provisioners":
            [
                {{
                "type": "shell",
                "script": "attacks/{attack}.sh"
                }}
            ]
        }}
        """
        # Build the template
        template = attack_template.format(attack = self.attack)
        (ret, out, err) = p.build(template, force=True)
        print (out)

    #Function which runs the network target machine build
    def create_network_target(self):
        print("Building the target machine =========================================")
        p = PackerExecutable("/usr/bin/packer")
        template = """{
            "builders": [
                {
                "type"                  : "virtualbox-ovf",
                "source_path"           : "virtual-machines/target.ova",
                "vm_name"               : "target",
                "boot_wait"             : "15m",
                "ssh_host"              : "192.168.0.15",
                "ssh_port"              : 22,
                "ssh_username"          : "Victim",
                "ssh_timeout"           : "20m",
                "ssh_password"          : "yeet",
                "ssh_skip_nat_mapping"  : "true"
                }
            ]
        }
        """
        # Build the template
        (ret, out, err) = p.build(template, force=True)
        print (out)

