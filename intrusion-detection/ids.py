import pyshark
import threading
import queue
import numpy as np

from joblib import dump, load
from sklearn.tree import DecisionTreeClassifier

class IDS():
    def __init__(self):
        # initialise the model
        idm = DetectionModel()
        # while the program is running
        while(True):
            print ("here")
            self.snif_packets()

            print ("moved on")
            # Process the data which was collected
            data = self.process_packets("out.cap")
            data = np.asarray(data)
            data = data.reshape(1, -1)
            print (data)

            # Predict whats happening on the network
            target = idm.predict(data)
            print (target)

    # Collect network packets
    def snif_packets(self):
        capture = pyshark.LiveCapture(interface='wlp3s0', output_file="out.cap")
        capture.set_debug()
        capture.sniff(timeout=1)


    def process_packets(self, capture):
        cap = pyshark.FileCapture(input_file=capture)
        # Initialise features
        tcp_packets = 0
        udp_packets = 0
        icmp_packets = 0
        tcpsrcports = []
        udpsrcports = []
        tcpdstports = []
        udpdstports = []
        sumfinflag = 0
        sumsynflag = 0
        sumpushflag = 0
        sumackflag = 0
        sumurgflag = 0 

        for packet in cap:
            if 'IP' in packet:
                # Get the protocol used
                protocol = int(packet.ip.proto)
                if protocol == 6:
                    tcp_packets += 1
                if protocol == 1:
                    icmp_packets += 1
                if protocol == 17:
                    udp_packets += 1

            if 'TCP' in packet:
                # Return the source port of the packet
                srcport = str(packet.tcp.srcport)
                tcpsrcports.append(srcport)

                # Destination port
                dstport = str(packet.tcp.dstport)
                tcpdstports.append(dstport)

                # Get the flags
                sumfinflag = sumfinflag + int(packet.tcp.flags_fin)
                sumsynflag = sumsynflag + int(packet.tcp.flags_syn)
                sumpushflag = sumpushflag + int(packet.tcp.flags_push)
                sumackflag = sumackflag + int(packet.tcp.flags_ack)
                sumurgflag = sumurgflag + int(packet.tcp.flags_urg)

            if 'UDP' in packet:
                # Return the source port of the packet
                srcport = str(packet.udp.srcport)
                udpsrcports.append(srcport)

                # Destination port
                dstport = str(packet.udp.dstport)
                udpdstports.append(dstport)
        
        # Find the amount of unique ports
        numtcpsrcports = len(set(tcpsrcports))
        numtcpdstports = len(set(tcpdstports))
        numudpsrcports = len(set(udpsrcports))
        numudpdstports = len(set(udpdstports))

        # append the newly found data to an array
        data = []
        # TCP
        data.append(tcp_packets)
        data.append(numtcpsrcports)
        data.append(numtcpdstports)
        data.append(sumfinflag)
        data.append(sumsynflag)
        data.append(sumpushflag)
        data.append(sumackflag)
        data.append(sumurgflag)
        # UDP
        data.append(udp_packets)
        data.append(numudpsrcports)
        data.append(numudpdstports)
        # ICMP
        data.append(icmp_packets)

        return data

class DetectionModel():

    def __init__(self):
        # Import the model
        self.idm = load('IDS.joblib')

    # Try to predict the threat
    def predict(self, data):
        value = self.idm.predict(data)
        return value
            
i = IDS()

