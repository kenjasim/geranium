import datagen
# Runs the vms for each attack one by one.

# ==========================================
# =         Normal Network Data            =
# ==========================================

# Run Normal Generator --------------------
# datagen.DataGen("normal")

# ==========================================
# =             DoS Attacks                =
# ==========================================

# Syn flood -------------------------------
# datagen.DataGen("synflood")

# UDP flood -------------------------------
# datagen.DataGen("udpflood")

# FIN Flood -------------------------------
# datagen.DataGen("finflood")

# # RST Flood -------------------------------
# datagen.DataGen("rstflood")

# # PSH and ACK Flood -----------------------
# datagen.DataGen("pshackflood")

# # ICMP and IGMP Flood ---------------------
# datagen.DataGen("icmpflood")

# # ==========================================
# # =             Probe Attack               =
# # ==========================================

# # Syn Scan --------------------------------
# datagen.DataGen("synscan")

# # Connect Scan ----------------------------
# datagen.DataGen("connectscan")

# # UDP Scan --------------------------------
# datagen.DataGen("udpscan")

# # Null Scan -------------------------------
# datagen.DataGen("nullscan")

# # FIN Scan --------------------------------
# datagen.DataGen("finscan")

# # Xmas Scan -------------------------------
# datagen.DataGen("xmasscan")

# # ACK Scan --------------------------------
# datagen.DataGen("ackscan")

# # Window Scan -----------------------------
# datagen.DataGen("windowscan")

# # IP Scan --------------------------------
# datagen.DataGen("ipscan")
