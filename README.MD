# Attack detector analysis script

## Description
The script analyzes a csv file with attack data and creates a new csv file with alert hashes of the attack detector that matched.
* To run the script, the csv file is passed as a command line arg to the run command `python3 index.py <path to csv file>`.
* If the name of the csv file is `attack.csv` and it's in the same directory as the script, the `run` command is -`python3 index.py attack.csv`
* The output is a new csv file(`Final_data.csv`) at the current working directory.
* The csv file must contain 3 major columns - `Attack Name`, `Network` and `ProtocolContracts`.  The script supports the 7 networks supported by Forta Network.
- `Attack_Detector.csv` contains attacks and the smart contract addresses of protocols involved.
- `Final_data.csv` contains the output of the script when applied on `Attack_Detector.csv`

