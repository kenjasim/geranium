# Runs a TCP Connect Scan probe attack

# Run the attack

timeout 10m bash -c -- 'while true
do
    nmap -sT 192.168.0.15
done'
