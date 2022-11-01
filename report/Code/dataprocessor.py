import pandas as pd
import pyshark

class DataProcessor():
    """ 
    Implimentation of the dataprocessing section of gerainum, the program will
    extract the features from the network data. Once collected it will collate the 
    packets and store into a dataset
    """

    def __init__(self, target, file_path, dataset_path, fltr):
        """ 
        The function is run when the data processing class is instantiated, the 
        function will take the configuration file variables and initiate variables
        needed later.

        Keyword Arguments
        target - The name of the attack to be parsed
        file_path - The network file to be read
        dataset_path - Path to write the packets to
        fltr - The filter to apply to the network packets
        """

        print("#######################")
        print("#   DATA PROCESSING   #")
        print("#######################")

        # Initilise the variables passed from config file
        self.file_path = file_path
        self.target = target
        self.dataset_path = dataset_path
        self.filter = fltr
        
        # Initialise the list to store the packets 
        self.packets = []

    def read_packets(self):
        """ 
        The network packets are read and the features extracted.
        """

        print("Reading File: " + self.file_path)
        print("--------------------------------------------------------------")

        self.cap = pyshark.FileCapture(input_file=self.file_path, display_filter =self.filter)

        print("File: " + self.file_path + " is now being processed")
        print("--------------------------------------------------------------")

        # Write the packets
        for packet in self.cap:

            if 'IP' in packet:
                # Get the protocol used
                protocol = int(packet.ip.proto)
                # Get the time that the packet was seen
                time = str(packet.sniff_time)

            if 'TCP' in packet:
                # Return the source port of the packet
                srcport = int(packet.tcp.srcport)

                # Destination port
                dstport = int(packet.tcp.dstport)

                # Get the flags
                finflag = int(packet.tcp.flags_fin)
                synflag = int(packet.tcp.flags_syn)
                pushflag = int(packet.tcp.flags_push)
                ackflag = int(packet.tcp.flags_ack)
                urgflag = int(packet.tcp.flags_urg)

                # Write to packet list
                data = [time, protocol, srcport, dstport, finflag, synflag, pushflag, ackflag, urgflag]
                self.packets.append(data)

            if 'UDP' in packet:
                # Return the source port of the packet
                srcport = int(packet.udp.srcport)

                # Destination port
                dstport = int(packet.udp.dstport)

                # Get the flags
                finflag = 0
                synflag = 0
                pushflag = 0
                ackflag = 0
                urgflag = 0

                # Write to packet list
                data = [time, protocol, srcport, dstport, finflag, synflag, pushflag, ackflag, urgflag]
                self.packets.append(data)

            if 'ICMP' in packet:
                # Return the source port of the packet
                srcport = 0

                # Destination port
                dstport = 0

                # Get the flags
                finflag = 0
                synflag = 0
                pushflag = 0
                ackflag = 0
                urgflag = 0

                # Write to packet list
                data = [time, protocol, srcport, dstport, finflag, synflag, pushflag, ackflag, urgflag]
                self.packets.append(data)

        # Collate the packets into a dataset
        self.collate_packets()

        print("File: " + self.dataset_path + " has been edited")
        print("------------------------------------------------")

    def collate_packets(self):
        """ 
        Collates the sniffed packets and extracts relevant features per second. These
        are then written to a CSV dataset.
        """

        # Import the data and index with the time
        datafrm = pd.DataFrame(self.packets)
        datafrm.columns = ["time", "protocol", "source_port", "destination_port", "finflag", "synflag", "pushflag", "ackflag", "urgflag"]
        print (datafrm.head)
        datafrm["time"] = pd.to_datetime(datafrm["time"], format='%Y-%m-%d %H:%M:%S')

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
