import os
import requests
import pandas as pd
from constants import VALID_NETWORKS, REQUIRED_COLUMNS
from collections import defaultdict
from bloom_filter import BloomFilter

from dotenv import load_dotenv
load_dotenv()

forta_api = "https://api.forta.network/graphql"
headers = {"content-type": "application/json",
           'Authorization': f"Bearer {os.getenv('FORTA_KEY')}"}
query = """
query exampleQuery($input: AlertsInput) {
  alerts(input: $input) {
    alerts {
      name
      addresses
      hash
      chainId
      truncated
      addressBloomFilter{
        k
        m
        bitset
        itemCount
      }
    }
    pageInfo {
      hasNextPage
      endCursor {
        blockNumber
        alertId
      }
    }
  }
}
"""


def get_alerts(start_date: str, end_date: str, chainid: str, bots: str) -> str:

    query_variables = {
        "input": {
            "first": 500,
            "blockDateRange": {
                "startDate": start_date,
                "endDate": end_date
            },
            "chainId": chainid,
            "bots": bots
        }
    }

    all_alerts = []
    next_page_exists = True

    while next_page_exists:
     # query Forta API
        payload = dict(query=query, variables=query_variables)
        try:
            response = requests.request(
                "POST", forta_api, json=payload, headers=headers)
            response.raise_for_status()
            # collect alerts
            if response.status_code == 200:
                data = response.json()['data']['alerts']
                alerts = data['alerts']
                all_alerts += alerts
        except requests.exceptions.HTTPError as errh:
            print("HTTP Error")
            print(errh.args[0])
        except requests.exceptions.ConnectionError as conerr:
            print("Connection error")
        except requests.exceptions.RequestException as errex:
            print("Exception request")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        # get next page of alerts if it exists
        next_page_exists = data['pageInfo']['hasNextPage']
        # endCursor contains alert Id and block number.
        # This is needed to get the next page of alerts.
        end_cursor = data['pageInfo']['endCursor']
        query_variables['input']['after'] = end_cursor
    # print(all_alerts)
    return all_alerts


def find_matching_hashes(df, alerts):
    # Create an empty list to store the matching hashes for each row
    new_lst = []
    # Iterate over each row in the DataFrame
    for index, row in df.iterrows():
        protocol_contracts = row['ProtocolContracts'].split(
            ',')  # Split the cell values
        # Store the matching hashes for the current row for TPs and FPs
        matching_hashes_to_addr_tp = defaultdict(list)
        matching_hashes_to_addr_fp = defaultdict(list)

        # Check each value in 'ProtocolContracts' against all addresses in the list of dictionaries
        for alert in alerts:
            bloomFilter = alert["addressBloomFilter"]
            if bloomFilter["itemCount"] > 0:
                b = BloomFilter(
                    {'k': bloomFilter["k"], 'm': bloomFilter["m"], 'bitset': bloomFilter["bitset"]})
                for contract in protocol_contracts:
                    if contract.strip() in alert['addresses'] or b.has(contract):
                        tp = False
                        for addr in row['Attacker'].split(','):
                            if addr.strip() in alert['addresses'] or b.has(addr):
                                matching_hashes_to_addr_tp[alert['hash']].append(
                                    contract)
                                tp = True
                                break
                        if not tp:
                            matching_hashes_to_addr_fp[alert['hash']].append(
                                contract)
            else:
                for contract in protocol_contracts:
                    if contract.strip() in alert['addresses']:
                        tp = False
                        for addr in row['Attacker'].split(','):
                            if addr.strip() in alert['addresses']:
                                matching_hashes_to_addr_tp[alert['hash']].append(
                                    contract)
                                tp = True
                                break
                        if not tp:
                            matching_hashes_to_addr_fp[alert['hash']].append(
                                contract)

        items_tp = matching_hashes_to_addr_tp.items()
        items_fp = matching_hashes_to_addr_fp.items()
        if items_tp:
            for hash, addresses in items_tp:
                new_row = row.copy()
                new_row["MatchingHashes_TP"] = hash
                new_row["matchingcontractaddresses"] = ','.join(addresses)
                new_lst.append(new_row)
        if items_fp:
            for hash, addresses in items_fp:
                new_row = row.copy()
                new_row["MatchingHashes_FP"] = hash
                new_row["matchingcontractaddresses"] = ','.join(addresses)
                new_lst.append(new_row)
        if not items_tp and not items_fp:
            new_lst.append(row)
    return pd.DataFrame(new_lst, columns=REQUIRED_COLUMNS +
                        ["MatchingHashes_TP", "MatchingHashes_FP", "matchingcontractaddresses"])


def clean_files(csv_file_path):
    # Read the CSV file into a DataFrame
    df = pd.read_csv(csv_file_path)

    # Check if all required columns are present

    missing_columns = set(REQUIRED_COLUMNS) - set(df.columns)
    if missing_columns:
        raise ValueError(
            f"The CSV file is missing one of the following required columns: {', '.join(missing_columns)}")

    # Filter rows based on the 'Network' column

    df = df[df['Network'].isin(VALID_NETWORKS)]

    # Drop rows with NaN values in 'ProtocolContracts' column
    df = df.dropna(subset=['ProtocolContracts'])

    # Drop unnecessary columns
    df = df.loc[:, REQUIRED_COLUMNS]

    # Data cleaning on 'ProtocolContracts'
    # Convert to lowercase
    df['ProtocolContracts'] = df['ProtocolContracts'].str.lower()
    df['ProtocolContracts'] = df['ProtocolContracts'].apply(lambda x: ','.join(filter(
        lambda y: y.startswith('0x') and len(y) == 42, x.split(','))))  # Filter and join valid values

    return df
