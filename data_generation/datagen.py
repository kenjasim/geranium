import os
import threading
import time
from packerpy import PackerExecutable

# Imoort data processing package
import sys
sys.path.append('..')
import data_processing


class DataGen():
    """ 
    Implimentation of the datagen section of gerainum, the program will
    take the relevent configurations and either generate and collect 
    normal network data or will spin up an attack and target machine and 
    collect network data of a specfic attack.
    """

    def __init__(self, 
                attack, 
                attack_path,
                executable_path, 
                tme, 
                attack_machine_path, 
                target_machine_path, 
                attack_username, 
                attack_password, 
                attack_ip,
                dataset_path,
                filter_ip):

        """ 
        The function is run when the data generation class is instantiated, If 
        the function requests normal network data then the traffic-gen is run
        but if an attack is requested then the attacks will be run on a virtual
        machine

        Keyword Arguments
        attack - The attack the user is running 
        attack_path - The path of the attack script to be used
        executable_path - The packer executable path
        tme - The time the user wants to run generation for
        attack_machine_path - Location of attack machine image
        target_machine_path - Location of target machine image
        attack_username - Username of attack machine
        attack_password - Password of attack machine
        attack_ip - IP of attack machine
        dataset_path - Location of dataset
        filter_ip - IP to filter network packets by
        """

        print("#######################")
        print("#   DATA GENERATION   #")
        print("#######################")
        
        # Collect all the arguments imputted by the user
        self.attack = attack
        self.attack_path = attack_path

        # Import all configuration file variables
        self.executable_path = executable_path
        self.time = tme
        self.attack_machine_path = attack_machine_path
        self.target_machine_path = target_machine_path
        self.attack_username = attack_username 
        self.attack_password = attack_password
        self.attack_ip = attack_ip
        self.dataset_path = dataset_path
        self.filter_ip = filter_ip
        #Check the arguments and run the relevent vms

        if self.attack == "normal":
            print("--------------------------------------------------------------")
            print("Normal Network Data Generation" )
            print("--------------------------------------------------------------")
            #start collecting network data
            capture = threading.Thread(target = self.sniff_packets)
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
            
            # Wait 30 seconds before collecting network data
            time.sleep(15)

            #start collecting network data
            print("Start Collecting Network Data")
            print("--------------------------------------------------------------")
            self.sniff_packets()

    # Runs an 7 machine and an attack machine to run exploits within it.
    def run_vms(self):
        """ 
        Starts the generation of the attack and target machines
        """
        #Create the attack machine in a seperate thread
        att = threading.Thread(target = self.create_attack_machine)
        att.start()

        #Create the other target machine in a seperate thread
        m1 = threading.Thread(target = self.create_network_target)
        m1.start()

    def ping_vm(self):
        """ 
        Pings the attack machine and returns the status of the machine

        Returns
        up - the status of the attack machine
        """
        response = os.system("ping -c 1 " + self.attack_ip + " 2>&1 >/dev/null")

        # Check if the machine is up
        if response == 0:
            return True
        else:
            return False

    #Run scapy and collect the network packets
    def sniff_packets(self):
        """ 
        Decalres a DataParser object and starts to sniff packets, once sniffed
        the packets will be collated
        """
        # Declares a data parser object
        parser = data_processing.DataParser(self.attack, self.dataset_path, self.time, self.filter_ip)

        # Starts to sniff packets
        parser.sniff_packets()


    #Function which runs the attack machine packer build
    def create_attack_machine(self):
        """ 
        Creates and fills in an attack template with the configuration varibles
        and builds the virtual machine from the template
        """
        # Declare the packer executable
        print("Building the attack machine: " + self.attack_machine_path + "\n""--------------------------------------------------------------")
        p = PackerExecutable(self.executable_path)

        # Build the attack template
        attack_template = """{{
            "builders": [
                {{
                "type"                  : "virtualbox-ovf",
                "vboxmanage"            : [
                                            ["modifyvm", "{{{{.Name}}}}", "--bridgeadapter1", "en0"]
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

        # Print an output after packer exits
        print (out)
        if err:
            print (err)

    #Function which runs the network target machine build
    def create_network_target(self):
        """ 
        Creates and fills in a target template with the configuration varibles
        and builds the virtual machine from the template
        """
        # Declare the packer executable
        print("Building the target machine: " + self.target_machine_path + "\n""--------------------------------------------------------------")
        p = PackerExecutable(self.executable_path)

        # Add a minute to the self time to allow the attack time
        target_time = 130 + self.time
        template = """{{
            "builders": [
                {{
                "type"                  : "virtualbox-ovf",
                "vboxmanage"            : [
                                            ["modifyvm", "{{{{.Name}}}}", "--bridgeadapter1", "en0"]
                                          ],
                "source_path"           : "{machine}",
                "vm_name"               : "target",
                "communicator"          : "none",
                "guest_additions_mode"  : "disable",
                "virtualbox_version_file": "",
                "boot_wait"             : "{time}s"
                }}
            ]
        }}
        """

        # Build the template
        template = template.format(machine = self.target_machine_path, time = target_time)
        (_, out, err) = p.build(template, force=True)

        # Print an output after packer exits
        print (out)
        if err:
            print (err)