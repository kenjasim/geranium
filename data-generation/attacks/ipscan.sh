# Runs a IP Scan probe attack

# Run the attack
timeout 10m bash -c -- 'while true
do
    nmap -sO 192.168.0.15/24
done'

