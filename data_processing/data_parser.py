import pandas as pd
from scapy.all import sniff

class DataParser():
    """ 
    Implimentation of the dataparser section of gerainum, the program will
    sniff network data and extract the features from the network data. Once
    collected it will collate the packets and store into a dataset
    """

    def __init__(self, target, dataset_path, time, filter_ip):
        """ 
        The function is run when the data parser class is instantiated, the 
        function will take the configuration file variables and initiate variables
        needed later.

        Keyword Arguments
        target - The name of the attack to be parsed
        dataset_path - Path to write the packets to
        time - The time to run the packet sniffing for
        filter_ip - The IP to filter the network data by
        """
        # Initilise flag values
        self.FIN = 0x01
        self.SYN = 0x02
        self.RST = 0x04
        self.PSH = 0x08
        self.ACK = 0x10
        self.URG = 0x20

        # Initilise the variables passed from config file
        self.target = target
        self.dataset_path = dataset_path
        self.time = time
        self.filter_ip = filter_ip

        # Define the list to store the packets 
        self.packets = []

    def sniff_packets(self):
        """ 
        Sniffs packets from all interfaces, if a filter ip is specified only packets from
        or to that IP will be sniffed.
        """
        if self.filter_ip == None:
            sniff(prn=self.process_packet, timeout=self.time)
        else:
            # Apply IP address filtering to only get the target machine filtered packets
            sniff(filter = "src " + self.filter_ip + " or host " + self.filter_ip, prn=self.process_packet, timeout=self.time)

        # Once filtered then collate packets
        self.collate_packets()
        

    def process_packet(self, packet):
        """ 
        Process a single packet which was sniffed, this is supplied to the sniff
        function.

        Keyword Arguments
        packet - The packet to be processed
        """
        # The time the oacket was sniffed
        time = packet.time

        if 'TCP' in packet:
            # Return the source port of the packet
            srcport = packet["TCP"].sport

            # Destination port
            dstport = packet["TCP"].dport

            # Get the fin flag
            if packet["TCP"].flags & self.FIN:
                finflag = 1
            else:
                finflag = 0

            # Get the syn flag
            if packet["TCP"].flags & self.SYN:
                synflag = 1
            else:
                synflag = 0

            # Get the push flag
            if packet["TCP"].flags & self.PSH:
                pushflag = 1
            else:
                pushflag = 0
            
            # Get the ack flag
            if packet["TCP"].flags & self.ACK:
                ackflag = 1
            else:
                ackflag = 0

            # Get the urg flag
            if packet["TCP"].flags & self.URG:
                urgflag = 1
            else:
                urgflag = 0    

            # Write the packets to the array
            data = [time, 6, srcport, dstport, finflag, synflag, pushflag, ackflag, urgflag, self.target]
            self.packets.append(data)

        if 'UDP' in packet:
            # Return the source port of the packet
            srcport = packet["UDP"].sport

            # Destination port
            dstport = packet["UDP"].dport

            # Write the packets to the array
            data = [time, 17, srcport, dstport, 0, 0, 0, 0, 0, self.target]
            self.packets.append(data)

        if 'ICMP' in packet:
            # write the data of the ICMP packets
            data = [time, 1, 0, 0, 0, 0, 0, 0, 0, self.target]
            self.packets.append(data)

    def collate_packets(self):
        """ 
        Collates the sniffed packets and extracts relevant features per second. These
        are then written to a CSV dataset.
        """

        # Import the data and index with the time
        datafrm = pd.DataFrame(self.packets)
        datafrm.columns = ["time", "protocol", "source_port", "destination_port", "finflag", "synflag", "pushflag", "ackflag", "urgflag", "target"]
        print (datafrm.head)
        datafrm["time"] = pd.to_datetime(datafrm["time"],unit='s')

        datafrm = datafrm.set_index("time")

        # Start writing the csv file
        text_file = open(self.dataset_path, "a")

        # Loop through each dataset per second
        for _, df in datafrm.groupby(pd.Grouper(freq='1s')):

            # Count the number of packets for each protocol
            protocol = df["protocol"].value_counts()
            tcp_packets = 0
            udp_packets = 0
            icmp_packets = 0
            if len(protocol) > 0:
                dic = protocol.to_dict()
                if 6 in dic.keys():
                    tcp_packets = dic[6]
                if 17 in dic.keys():
                    udp_packets = dic[17]
                if 1 in dic.keys():
                    icmp_packets = dic[1]

            tcpsrcports = 0
            udpsrcports = 0
            # Return the source port of all packets
            srcport = df[["protocol", "source_port"]]
            for _, src in srcport.groupby("protocol"):
                if (not(src[src["protocol"] == 6].empty)):
                    tcpsrcports = len(src["source_port"].value_counts())
                if (not(src[src["protocol"] == 17].empty)):
                    udpsrcports = len(src["source_port"].value_counts()) 
                
            tcpdstports = 0
            udpdstports = 0
            # Return the destination of all packets
            dstport = df[["protocol", "destination_port"]]
            for _, dst in dstport.groupby("protocol"):
                if (not(dst[dst["protocol"] == 6].empty)):
                    tcpdstports = len(dst["destination_port"].value_counts())
                if (not(dst[dst["protocol"] == 17].empty)):
                    udpdstports = len(dst["destination_port"].value_counts())


            # Get the flags
            finflag = df["finflag"].sum()
            synflag = df["synflag"].sum()
            pushflag = df["pushflag"].sum()
            ackflag = df["ackflag"].sum()
            urgflag = df["urgflag"].sum()

            # Write to the dataset
            new_row = str(tcp_packets) + ',' + str(tcpsrcports) + ',' + str(tcpdstports) + ',' + str(finflag) + ',' + str(synflag) + ',' + str(pushflag) + ',' + str(ackflag) + ',' + str(urgflag) + ',' + str(udp_packets) + ',' + str(udpsrcports) + ',' + str(udpdstports) + ',' + str(icmp_packets) +',' + self.target
            text_file.write(new_row)
            text_file.write("\n")
        
        text_file.close()

