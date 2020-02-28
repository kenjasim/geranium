import parser
import threading
# Script to parse all the data generated from the packet collection
# normal
p = parser.Parser("normal")
p.write_csv('../data-generation/capture/normal.pcapng', 'data/normal.csv', None)

# fin flood
# p = parser.Parser("finflood")
# p.write_csv('../data-generation/capture/finflood.pcapng', 'data/finflood.csv', 'ip.addr == 192.168.0.15')

# # synflood
# p = parser.Parser("synflood")
# p.write_csv('../data-generation/capture/synflood.pcapng', 'data/synflood.csv', 'ip.addr == 192.168.0.15')

# # pshackflood
# p = parser.Parser("pshackflood")
# p.write_csv('../data-generation/capture/pshackflood.pcapng', 'data/pshackflood.csv', 'ip.addr == 192.168.0.15')

# udpflood
# p = parser.Parser("udpflood")
# p.write_csv('../data-generation/capture/udpflood.pcapng', 'data/udpflood.csv', 'ip.addr == 192.168.0.15')

