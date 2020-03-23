import pandas as pd
from scapy.all import sniff

class DataParser():

    def __init__(self, target, dataset_path, time):
        # Initilise flag values
        self.FIN = 0x01
        self.SYN = 0x02
        self.RST = 0x04
        self.PSH = 0x08
        self.ACK = 0x10
        self.URG = 0x20

        self.target = target
        self.dataset_path = dataset_path
        self.time = time

        # Define the list to store the packets 
        self.packets = []

    def sniff_packets(self):
        sniff(prn=self.process_packet, timeout=self.time)

    def process_packet(self, packet):
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

            data = [6, srcport, dstport, finflag, synflag, pushflag, ackflag, urgflag, self.target]
            self.packets.append(data)

        if 'UDP' in packet:
            # Return the source port of the packet
            srcport = packet["UDP"].sport

            # Destination port
            dstport = packet["UDP"].dport

            data = [17, srcport, dstport, 0, 0, 0, 0, 0, self.target]
            self.packets.append(data)

        if 'ICMP' in packet:
            # write the data of the ICMP packets
            data = [1, 0, 0, 0, 0, 0, 0, 0, self.target]
            self.packets.append(data)

    def collate_packets(self):

        # Import the data and index with the time
        datafrm = pd.DataFrame(self.packets)
        datafrm['time'] = pd.to_datetime(datafrm['time'], format='%Y-%m-%d %H:%M:%S')
        datafrm = datafrm.set_index('time')

        # Start writing the csv file
        text_file = open(self.dataset_path, "a")

        for _, df in datafrm.groupby(pd.Grouper(freq='1s')):

            protocol = df[0].value_counts()
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
            # Return the source port of the packet
            srcport = df[[0, 1]]
            for _, src in srcport.groupby(0):
                if (not(src[src[0] == 6].empty)):
                    tcpsrcports = len(src[1].value_counts())
                if (not(src[src[0] == 17].empty)):
                    udpsrcports = len(src[1].value_counts()) 
                
            tcpdstports = 0
            udpdstports = 0
            # Destination port
            dstport = df[[0, 2]]
            for _, dst in dstport.groupby(0):
                if (not(dst[dst[0] == 6].empty)):
                    tcpdstports = len(dst[2].value_counts())
                if (not(dst[dst[0] == 17].empty)):
                    udpdstports = len(dst[2].value_counts())


            # Get the flags
            finflag = df[3].sum()
            synflag = df[4].sum()
            pushflag = df[5].sum()
            ackflag = df[6].sum()
            urgflag = df[7].sum()

            # Write to the dataset
            new_row = str(tcp_packets) + ',' + str(tcpsrcports) + ',' + str(tcpdstports) + ',' + str(finflag) + ',' + str(synflag) + ',' + str(pushflag) + ',' + str(ackflag) + ',' + str(urgflag) + ',' + str(udp_packets) + ',' + str(udpsrcports) + ',' + str(udpdstports) + ',' + str(icmp_packets) +',' + self.target
            text_file.write(new_row)
            text_file.write("\n")
        
        text_file.close()
