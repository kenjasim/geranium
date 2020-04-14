# Geranium
Python scripts to allow the generation of network data from virtual machines, the processing of the data and thus the building of machine learning models.

## Prerequisites
You must have packer installed to run anything in ```generate``` command. This can be downloaded [from here](https://packer.io/downloads.html).

Once packer is installed you must have 2 virtualbox ova files. These are preconfigured virtual machines which can be exported from VirtualBox following [these instructions](https://docs.oracle.com/cd/E26217_01/E26796/html/qs-import-vm.html). You must either create an attack machine (Kali was used in testing) and a target machine (a Windows 7 machine was used in testing). Alternativly the testing machines used can be downloaded 

If you are using Ubuntu linux then you can install virtualbox and Packer by running
```
    sudo ./install_linux.sh
```

pyshark is needed along with pandas for data processing .PCAPNG wireshark data files if you prefer to use that, however only scapy and pandas are used for processing in the ```generate``` phase 

Finally to install depandancies run:

```
sudo python3 setup.py install
```

## Usage

### Generate
To generate data you must first create an attack to generate data from. For example using the metasploit framework a synflood attack may look like

```bash
service postgresql start

msfdb init

timeout 10m msfconsole -q -x "use auxiliary/dos/tcp/synflood;set RHOST <IP>; exploit;"
```
Next alter the config file:
- ```executable_path```: Packer executable path
- ```time```: Time in seconds to run the generation
- ```attack_machine_path```: Location of attack machine
- ```target_machine_path```: Location of target machine
- ```attack_username```: Attack machine ssh username
- ```attack_password```: Attack machine ssh password
- ```attack_ip```: Attack machine IP
- ```filter_ip```: IP of target machine to filter from
- ```interface```: The interface you are bridging
- ```dataset_path```: Location of the dataset, found under ```data-processing```

Once an attack has been made and the config file altered correctly then you can use

```
    sudo ./geranium.py generate synflood <path/to/synflood_attack.sh>
```
This will run for the alloted time as defined in the config file and will generate a CSV with features as defined in ``` data_processing/data_parser.py```.

#### Generating Normal Network Data

To generate normal data run:

```
    sudo ./geranium.py generate normal
```

This used the web-traffic-generator from: https://github.com/ecapuano/web-traffic-generator. You only need to specify the time in the config file for this.
### Clearing the Virtual Machines
On exit all the relevant folders for the virtual machines should have been removed, but if not you can run:

```
    sudo ./geranium.py clearvms
```

### Process

For any .PCAPNG wireshark files which may have been generated and contain useful data the process command can create a CSV from them.

First alter the config file:
- ```dataset_path```: Location of the dataset
- ```filter```: A filter to filter the packets

Then you can process, for the synflood example above:

```
    sudo ./geranium.py process synflood <path/to/synflood_network_data>
```

This part requires both pyshark and pandas

NOTE: this is not a neccesary step if you have generated using the native ```generate``` command.

### Model

An example decision tree is provided. This was generated using sklearn.

To generate a decision tree from the data, first alter the config file:

- ```model_path```: Path to store model
- ```classes```: Classes found in dataset (List)

From here a decision tree model can be generated using:

```
    sudo ./geranium.py model <path/to/dataset>
```

### IDS

For a rudementary intrusion detection system you can specify the model in the config file:

- ```model```: Place to locate the model

Then the intrusion detection system can be run with the command

```
    sudo ./geranium.py ids
```