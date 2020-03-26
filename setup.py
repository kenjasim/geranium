import os
from setuptools import setup

# Find the root folder
root_folder = os.path.dirname(os.path.realpath(__file__))

# Find the requirements.txt
requirementPath = root_folder + '/requirements.txt'
install_requires = [] 

# Add all requirements to be installed
if os.path.isfile(requirementPath):
    with open(requirementPath) as f:
        install_requires = f.read().splitlines()

with open("README.md", 'r') as f:
    long_description = f.read()
# Run the setup
setup(name="geranium", 
      version='0.3', 
      description='Python scripts to allow the generation of network data from virtual machines for intrusion detection systems',
      install_requires=install_requires,
      author = "Kenan Jasim")