# Attack detector analysis script

## Description

This script takes a csv file as input. The csv file must contain 3 major columns - Attack Name, Network and ProtocolContracts. The output is a new csv file(`Final_data.csv`) with hashes of the matching alerts from the attack detector bot at the current working directory

### To run the script, 
run the command  `python3 index.py <link to csv file>` e.g `python3 index.py attack.csv`
