import pandas as pd
import parser

text_file = open("../intrusion-detection/dataset.csv", "w")
text_file.write("tcp_packets, tcp_source_port, tcp_destination_port, tcp_fin_flag, tcp_syn_flag, tcp_push_flag, tcp_ack_flag, tcp_urgent_flag, udp_packets, udp_source_port, udp_destination_port, icmp_packets, target")
text_file.write("\n")
# Collect the data from the packets and save them as csvs
# normal
p = parser.Parser("normal")
p.write_csv('../data-generation/capture/normal.pcapng', 'data/normal.csv', None)
p.create_csv_rows("data/normal.csv", "normal", text_file)
p.create_csv_rows("data/normal2.csv", "normal", text_file)

# fin flood
p = parser.Parser("finflood")
p.write_csv('../data-generation/capture/finflood.pcapng', 'data/finflood.csv', 'ip.addr == 192.168.0.15')
p.create_csv_rows("data/finflood.csv", "finflood", text_file)

# synflood
p = parser.Parser("synflood")
p.write_csv('../data-generation/capture/synflood.pcapng', 'data/synflood.csv', 'ip.addr == 192.168.0.15')
p.create_csv_rows("data/synflood.csv", "synflood", text_file)

# pshackflood
p = parser.Parser("pshackflood")
p.write_csv('../data-generation/capture/pshackflood.pcapng', 'data/pshackflood.csv', 'ip.addr == 192.168.0.15')
p.create_csv_rows("data/pshackflood.csv", "pshackflood", text_file)

# udpflood
p = parser.Parser("udpflood")
p.write_csv('../data-generation/capture/udpflood.pcapng', 'data/udpflood.csv', 'ip.addr == 192.168.0.15')
p.create_csv_rows("data/udpflood.csv", "udpflood", text_file)

# Close the text file when done
text_file.close()



