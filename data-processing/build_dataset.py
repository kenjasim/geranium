import pandas as pd
import parser

# Collect the data from the packets and save them as csvs
# normal
p = parser.Parser("normal")
p.write_csv('../data-generation/capture/normal.pcapng', 'data/normal.csv', None)

# fin flood
p = parser.Parser("finflood")
p.write_csv('../data-generation/capture/finflood.pcapng', 'data/finflood.csv', 'ip.addr == 192.168.0.15')

# synflood
p = parser.Parser("synflood")
p.write_csv('../data-generation/capture/synflood.pcapng', 'data/synflood.csv', 'ip.addr == 192.168.0.15')

# pshackflood
p = parser.Parser("pshackflood")
p.write_csv('../data-generation/capture/pshackflood.pcapng', 'data/pshackflood.csv', 'ip.addr == 192.168.0.15')

# udpflood
p = parser.Parser("udpflood")
p.write_csv('../data-generation/capture/udpflood.pcapng', 'data/udpflood.csv', 'ip.addr == 192.168.0.15')

# import all the data as pandas dataframes
normal = pd.read_csv("data/normal.csv")
normal2 = pd.read_csv("data/normal2.csv")
synflood = pd.read_csv("data/synflood.csv")
udpflood = pd.read_csv("data/udpflood.csv")
finflood = pd.read_csv("data/finflood.csv")
pshackflood = pd.read_csv("data/pshackflood.csv")

text_file = open("../intrusion-detection/dataset.csv", "w")
text_file.write("tcp_packets, tcp_source_port, tcp_destination_port, tcp_fin_flag, tcp_syn_flag, tcp_push_flag, tcp_ack_flag, tcp_urgent_flag, udp_packets, udp_source_port, udp_destination_port, icmp_packets, target")
text_file.write("\n")

def create_csv_rows(datafrm, name):
    print(name)
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
        text_file.write(new_row)
        text_file.write("\n")


create_csv_rows(normal, "normal")
create_csv_rows(normal2, "normal")
create_csv_rows(synflood, "synflood")
create_csv_rows(udpflood, "udpflood")
create_csv_rows(finflood, "finflood")
create_csv_rows(pshackflood, "pshackflood")

text_file.close()



