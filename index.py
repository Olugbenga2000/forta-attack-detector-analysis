import pandas as pd
import argparse
from constants import NETWORKS_TO_ID, START_DATE, END_DATE, BOTS
from utils import get_alerts, find_matching_hashes, clean_files


def process_file(csv_file_path):
    df = clean_files(csv_file_path)
    print(df)
    # Create separate DataFrames for each unique value in 'Network' column
    existing_networks = df['Network'].unique()
    dfs = {value: df[df['Network'] == value].copy()
           for value in existing_networks}
    network_to_alerts = {}
    for nets in existing_networks:
        network_to_alerts[nets] = get_alerts(
            START_DATE, END_DATE, NETWORKS_TO_ID[nets], BOTS)
    combined_dfs = []
    # Loop through unique_nets and find_matching_hashes for each net
    for nets in existing_networks:
        combined_dfs.append(find_matching_hashes(
            dfs[nets], network_to_alerts[nets]))
    # Concatenate the list of DataFrames into a single DataFrame
    merged_df = pd.concat(combined_dfs, ignore_index=True)
    merged_df.to_csv('Final_data.csv')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process a CSV file.')
    parser.add_argument('csv_file', help='Path to the CSV file')

    args = parser.parse_args()

    process_file(args.csv_file)
