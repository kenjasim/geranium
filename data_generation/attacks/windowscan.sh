# Runs a TCP Window Scan probe attack

# Run the attack
timeout 10m bash -c -- 'while true
do
    nmap -sW 192.168.0.15/24
done'

