import requests
import pandas as pd
from constants import VALID_NETWORKS, REQUIRED_COLUMNS
from collections import defaultdict
from bloom_filter import BloomFilter

forta_api = "https://api.forta.network/graphql"
headers = {"content-type": "application/json"}
query = """
query exampleQuery($input: AlertsInput) {
  alerts(input: $input) {
    alerts {
      name
      addresses
      hash
      chainId
      addressBloomFilter
      truncated
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
    print(all_alerts)
    return all_alerts


def find_matching_hashes(df, alerts):
    # Create an empty list to store the matching hashes for each row
    new_lst = []
    # Iterate over each row in the DataFrame
    for index, row in df.iterrows():
        protocol_contracts = row['ProtocolContracts'].split(
            ',')  # Split the cell values
        # Store the matching hashes for the current row
        matching_hashes_to_addr = defaultdict(list)

        # Check each value in 'ProtocolContracts' against all addresses in the list of dictionaries
        for alert in alerts:
            b = BloomFilter({'k': alert.addressBloomFilter.k, 'm': alert.addressBloomFilter.k,
                            'bitset': alert.addressBloomFilter.content})
            print(b)
            for contract in protocol_contracts:
                if contract.strip() in alert['addresses'] or alert.has_address(contract):
                    matching_hashes_to_addr[alert['hash']].append(contract)
        items = matching_hashes_to_addr.items()
        if items:
            for hash, addresses in items:
                new_row = row.copy()
                new_row["MatchingHashes"] = hash
                new_row["matchingcontractaddresses"] = ','.join(addresses)
                new_lst.append(new_row)
        else:
            new_lst.append(row)
    return pd.DataFrame(new_lst, columns=REQUIRED_COLUMNS +
                        ["MatchingHashes", "matchingcontractaddresses"])


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


# get_alerts("2023-05-01", "2023-06-30", "1",
#            ['0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1'])
