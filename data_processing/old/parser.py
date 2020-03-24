import pyshark
import pandas as pd

class Parser():

    def __init__(self, target):
        self.target = target
        print(self.target)

    def write_csv (self, input_file, output_file, filter):
        # Read the capture file
        self.cap = pyshark.FileCapture(input_file=input_file, display_filter =filter)

        # print the file
        print (self.cap)

        # Open a text file
        text_file = open(output_file, "a")
        text_file.write("time, protocol, source_port, destination_port, fin_flag, syn_flag, push_flag, ack_flag, urgent_flag, target")
        text_file.write("\n")

        # Write the packets
        for packet in self.cap:

            if 'IP' in packet:
                # Get the protocol used
                protocol = str(packet.ip.proto)
                # Get the time that the packet was seen
                time = str(packet.sniff_time)

            if 'TCP' in packet:
                # Return the source port of the packet
                srcport = str(packet.tcp.srcport)

                # Destination port
                dstport = str(packet.tcp.dstport)

                # Get the flags
                finflag = str(packet.tcp.flags_fin)
                synflag = str(packet.tcp.flags_syn)
                pushflag = str(packet.tcp.flags_push)
                ackflag = str(packet.tcp.flags_ack)
                urgflag = str(packet.tcp.flags_urg)

                new_pack = time + ',' + protocol + ',' + srcport + ',' + dstport + ',' + finflag + ',' + synflag + ',' + pushflag + ',' + ackflag + ',' + urgflag + ',' + self.target
            
                text_file.write(new_pack)
                text_file.write("\n")

            if 'UDP' in packet:
                # Return the source port of the packet
                srcport = str(packet.udp.srcport)

                # Destination port
                dstport = str(packet.udp.dstport)

                # Get the flags
                finflag = str(0)
                synflag = str(0)
                pushflag = str(0)
                ackflag = str(0)
                urgflag = str(0)

                # put into comma seperated format
                new_pack = time + ',' + protocol + ',' + srcport + ',' + dstport + ',' + finflag + ',' + synflag + ',' + pushflag + ',' + ackflag + ',' + urgflag + ',' + self.target
                
                text_file.write(new_pack)
                text_file.write("\n")

            if 'ICMP' in packet:
                # Return the source port of the packet
                srcport = str(0)

                # Destination port
                dstport = str(0)

                # Get the flags
                finflag = str(0)
                synflag = str(0)
                pushflag = str(0)
                ackflag = str(0)
                urgflag = str(0)

                # put into comma seperated format
                new_pack = time + ',' + protocol + ',' + srcport + ',' + dstport + ',' + finflag + ',' + synflag + ',' + pushflag + ',' + ackflag + ',' + urgflag + ',' + self.target 
                
                text_file.write(new_pack)
                text_file.write("\n")
        
        text_file.close()

    def create_csv_rows(self, file, name, dataset):
        datafrm = pd.read_csv(file)
        datafrm['time'] = pd.to_datetime(datafrm['time'], format='%Y-%m-%d %H:%M:%S')

        datafrm = datafrm.set_index('time')

        for _, df in datafrm.groupby(pd.Grouper(freq='1s')):
            protocol = df[" protocol"].value_counts()
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
            srcport = df[[" protocol", " source_port"]]
            for _, src in srcport.groupby(" protocol"):
                if (not(src[src[' protocol'] == 6].empty)):
                    tcpsrcports = len(src[" source_port"].value_counts())
                if (not(src[src[' protocol'] == 17].empty)):
                    udpsrcports = len(src[" source_port"].value_counts()) 
                
            tcpdstports = 0
            udpdstports = 0
            # Destination port
            dstport = df[[" protocol", " destination_port"]]
            for _, dst in dstport.groupby(" protocol"):
                if (not(dst[dst[' protocol'] == 6].empty)):
                    tcpdstports = len(dst[" destination_port"].value_counts())
                if (not(dst[dst[' protocol'] == 17].empty)):
                    udpdstports = len(dst[" destination_port"].value_counts())


            # Get the flags
            finflag = df[" fin_flag"].sum()
            synflag = df[" syn_flag"].sum()
            pushflag = df[" push_flag"].sum()
            ackflag = df[" ack_flag"].sum()
            urgflag = df[" urgent_flag"].sum()
            
            # create row
            new_row = str(tcp_packets) + ',' + str(tcpsrcports) + ',' + str(tcpdstports) + ',' + str(finflag) + ',' + str(synflag) + ',' + str(pushflag) + ',' + str(ackflag) + ',' + str(urgflag) + ',' + str(udp_packets) + ',' + str(udpsrcports) + ',' + str(udpdstports) + ',' + str(icmp_packets) +',' +name
            dataset.write(new_row)
            dataset.write("\n")
