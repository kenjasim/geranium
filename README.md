# proactive-ids
Python scripts to allow the generation of network data from virtual machines, the processing of the data and thus the building of machine learning models.

## Prerequisites
You must have packer installed to run anything in ``` data-generation```. This can be downloaded [from here](https://packer.io/downloads.html).

Once packer is installed you must have 2 virtualbox ova files. These are preconfigured virtual machines which can be exported from VirtualBox following [these instructions](https://docs.oracle.com/cd/E26217_01/E26796/html/qs-import-vm.html). You must create an attack machine (Kali was used in testing) and a target machine (a Windows 7 machine was used in testing.) They must be stored in the ```data-generation``` folder

Wireshark is needed for data collection and pyshark is needed along with pandas for data processing

## Usage
To generate data you must first create an attack to generate data from. For example using the metasploit framework a synflood attack may look like

```bash
service postgresql start

msfdb init

timeout 10m msfconsole -q -x "use auxiliary/dos/tcp/synflood;set RHOST <IP>; exploit;"
```

Once this is stored in the attacks folder you can run the data generation by

```
./geranium.py attack
```
This will run for 10 minutes and store the packet data into a pcapng file.

From here the file may be processed by running the data parser, an example can be seen in the ```builddataset.py``` file.

An example decision tree is provided. This was generated using sklearn.