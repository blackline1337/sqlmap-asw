#sql_agressive glued together minimizing the amount of scripts required
import csv
import time
import requests
import argparse
from colorama import Fore, Style
from tqdm import tqdm

def attack_surface(input_file, start_line):
    with open(input_file, 'r') as file:
        reader = csv.reader(file)
        for _ in range(start_line):
            next(reader)
        data = [row for row in reader]

    result = [row[2] for row in data]

    return result

def shodan_query(domain):
    api_key = ""
    api_endpoint = f'https://api.shodan.io/dns/domain/{domain}?key={api_key}'

    try:
        response = requests.get(api_endpoint)
        response.raise_for_status()
        result = response.json()

        a_records = [entry['value'] for entry in result['data'] if entry.get('type') == 'A']

        print(f"{Fore.GREEN}[ Found results for - {Style.RESET_ALL}{domain} - Saving....")

        return a_records

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error: {domain} no results found!{Style.RESET_ALL}")
        return []

def remove_duplicates(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Use a set to remove duplicates and preserve order
    unique_lines = sorted(set(lines))

    with open(file_path, 'w') as file:
        file.writelines(unique_lines)

def main():
    parser = argparse.ArgumentParser(description='Process domains with Shodan.')
    parser.add_argument('--start_line', type=int, default=81478, help='Line number to start processing from')
    parser.add_argument('--sort_file', action='store_true', help='Sort and remove duplicates from the file')
    parser.add_argument('--input_file', help='Read domains list')
    args = parser.parse_args()

    if args.sort_file:
        remove_duplicates('attack_surface.txt')
        print(f"{Fore.CYAN}Duplicates removed and file sorted{Style.RESET_ALL}")
        return  # Exit the script if --sort_file is provided

    input_file = args.input_file
    result = attack_surface(input_file, args.start_line)

    with tqdm(total=len(result), desc="Processing Domains", unit="domain") as pbar:
        for domain in result:
            a_records = shodan_query(domain)
            if a_records:
                # Append the results to the file
                with open('attack_surface.txt', 'a') as output_file:
                    output_file.write('\n'.join(a_records) + '\n')
                    # print(f"{Fore.CYAN}Results appended to attack_surface.txt{Style.RESET_ALL}")
            time.sleep(1.3)  # Introduce a delay of 1.2 seconds
            pbar.update(1)
            pbar.set_postfix(remaining=len(result) - pbar.n, percent=(pbar.n / pbar.total) * 100)

if __name__ == "__main__":
    main()
