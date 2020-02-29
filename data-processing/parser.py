import pyshark

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
        text_file = open(output_file, "w")
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

