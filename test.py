import unittest
import os
import time
from pathlib import Path

import data_generation
import data_processing
import data_modeling



class TestCases(unittest.TestCase):

    def test_normal_generation(self):
        """
        Test that normal data can be generated
        """

        data_generation.DataGen("normal",
                                None,
                                None,
                                10,
                                None,
                                None,
                                None,
                                None,
                                None,
                                "data.csv",
                                None)
        
        time.sleep(1)
        self.assertTrue(os.path.exists("data.csv") and os.path.getsize("data.csv") > 0)

    def test_attack_generation(self):
        """
        Test that attack data can be generated using synflood
        """

        data_generation.DataGen("synflood",
                                "data_generation/attacks/synflood.sh",
                                "/usr/local/bin/packer",
                                60,
                                "data_generation/virtual-machines/attack.ova",
                                "data_generation/virtual-machines/target.ova",
                                "root",
                                "yeet",
                                "192.168.0.14",
                                "data.csv",
                                "192.168.0.15")
        
        time.sleep(1)
        self.assertTrue(os.path.exists("data.csv") and os.path.getsize("data.csv") > 0)

    def test_network_collection(self):
        """
        Test that network data can be collected
        """

        data_processing.DataParser("normal", 
                                   "data.csv", 
                                   10, 
                                   None)
        time.sleep(1)
        self.assertTrue(os.path.exists("data.csv") and os.path.getsize("data.csv") > 0)


    def test_data_processing(self):
        """
        Test that wireshark data can be generated
        """

        data_processing.DataProcessor("normal", 
                                      "data_generation/capture/normal.pcapng", 
                                      "data.csv", 
                                      None)
        
        time.sleep(1)
        self.assertTrue(os.path.exists("data.csv") and os.path.getsize("data.csv") > 0)

    def test_model_generation(self):
        """
        Test that a decision tree model can be generated from data
        """
        data_modeling.DataModeling("dataset.csv", 
                                   "model.joblib", 
                                   ["normal", "synflood", "udpflood", "finflood", "pshackflood"])
        time.sleep(1)
        self.assertTrue(os.path.exists("model.joblib") and os.path.getsize("model.joblib") > 0)

    def test_full_system(self):
        """
        Run a full test scenario using geranium.py
        """

        os.system("./geranium.py generate normal")
        os.system("./geranium.py generate synflood data_generation/attacks/synflood.sh")
        os.system("./geranium.py generate udpflood data_generation/attacks/udpflood.sh")
        os.system("./geranium.py generate finflood data_generation/attacks/finflood.sh")
        os.system("./geranium.py generate pshackflood data_generation/attacks/pshackflood.sh")
        os.system("./geranium.py model dataset.csv")

        time.sleep(1)

        self.assertTrue(os.path.exists("IDS.joblib") and os.path.getsize("IDS.joblib") > 0)

    
    def tearDown(self):
        # release resources
        print("finished running " + self._testMethodName)
        if os.path.exists("data.csv"):
            os.remove("data.csv")
        if os.path.exists("model.joblib"):
            os.remove("model.joblib")


if __name__ == '__main__':
    unittest.main()
