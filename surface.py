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
        line_count = 0

        # Skip lines up to the specified start_line
        for _ in range(start_line):
            next(reader)
            line_count += 1

        # Output the start_line count
        print(f"Start line count: {line_count}")

        # Read the remaining lines and store them in the data list
        data = [row for row in reader]
        line_count += len(data)

    result = [row[2] for row in data]

    print(f"Total lines read: {line_count}")

    return result

def shodan_query(domain):
    api_key = ""
    api_endpoint = f'https://api.shodan.io/dns/domain/{domain}?key={api_key}'

    try:
        response = requests.get(api_endpoint)
        response.raise_for_status()
        result = response.json()

        a_records = [entry['value'] for entry in result['data'] if entry.get('type') == 'A']
        # leave this here for debugging
        #print(f"{Fore.GREEN}[ Found results for - {Style.RESET_ALL}{domain}:{a_records} - Saving....")

        return a_records, True

    except requests.exceptions.RequestException as e:
        #leave this here for debugging
        #print(f"{Fore.RED}Error: {domain} no results found!{Style.RESET_ALL}")
        return [], False

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

    domains_found_count = 0  # Initialize the count of domains found

    with tqdm(total=len(result), desc="Processing Domains", unit="domain") as pbar:
        for domain in result:
            a_records, domain_found = shodan_query(domain)
            if domain_found:
                domains_found_count += 1  # Increment the count of domains found

                # Append the results to the file
                with open('surface_output/attack_surface.txt', 'a') as output_file:
                    output_file.write('\n'.join(a_records) + '\n')
                
            time.sleep(1.3)  # Introduce a delay of 1.2 seconds
            pbar.update(1)
            pbar.set_postfix(remaining=len(result) - pbar.n, percent=(pbar.n / pbar.total) * 100, domains_found=domains_found_count)

    print(f"Next run should process the last {len(result)} lines from the bottom")
    print(f"Total domains found: {domains_found_count}")

if __name__ == "__main__":
    main()

