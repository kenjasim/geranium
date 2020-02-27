import pyshark

class Parser():

    def __init__(self):
        pass

    def read_file(self, file_path):
        # Read the capture file
        self.cap = pyshark.FileCapture(input_file=file_path)

        # print the file
        print (self.cap)

        # Open a text file
        text_file = open("sample.txt", "w")

        # Write the packets
        for packet in self.cap:
            text_file.write(str(packet))
            text_file.write("--------------------------------------------------------------")
        
        text_file.close()

p = Parser()
p.read_file('../capture/data/normal_filtered.pcapng')