# Runs a TCP Null Scan probe attack

# Run the attack
timeout 10m bash -c -- 'while true
do
    nmap -sN 192.168.0.15
done'