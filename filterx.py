import argparse

def sort_and_prioritize_http(input_file, output_file):
    with open(input_file, 'r') as file:
        lines = file.readlines()

    # Create a dictionary to store IPs with the priority of HTTP over HTTPS
    ip_dict = {}

    for line in lines:
        parts = line.strip().split('://')
        if len(parts) == 2:
            protocol, ip = parts
            ip_dict[ip] = protocol

    # Prioritize HTTP over HTTPS
    sorted_ips = [f'http://{ip}' if protocol == 'http' else f'https://{ip}' for ip, protocol in ip_dict.items()]
    
    with open(output_file, 'w') as file:
        for sorted_ip in sorted_ips:
            file.writelines(sorted_ip+"\n")



def main():
    parser = argparse.ArgumentParser(description='Sort and prioritize IP addresses.')
    parser.add_argument('--input_file', required=True, help='Path to the input file containing IP addresses.')
    parser.add_argument('--output_file', required=True, help='Path to the output file for sorted IP addresses.')
    args = parser.parse_args()

    sort_and_prioritize_http(args.input_file, args.output_file)

if __name__ == "__main__":
    main()
