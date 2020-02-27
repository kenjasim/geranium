# Runs a SYN Scan probe attack

# Run the attack
timeout 10m bash -c -- 'while true
do
    nmap -sS 192.168.0.15
done'
