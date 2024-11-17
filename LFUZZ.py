import socket
import dns.resolver
import time
import concurrent.futures
from queue import Queue
import threading
import argparse  # Import argparse

# Function to check if a subdomain resolves to an IP address
def check_subdomain(domain):
    try:
        # Using socket for basic resolution
        ip = socket.gethostbyname(domain)
        print(f"[+] Found: {domain} -> {ip}")
        return domain  # Return the found domain
    except socket.gaierror:
        pass  # Ignore if it doesn't resolve

    # Optionally, use dnspython for more detailed DNS queries
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'A')  # 'A' record for IPv4 address
        for rdata in answers:
            print(f"[+] Found: {domain} -> {rdata.to_text()}")
        return domain
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass  # Ignore if no answer or domain doesn't exist
    
    return None  # If no valid result is found

# Function to process and fuzz subdomains for a given root domain
def fuzz_subdomains_for_domain(domain, subdomains, result_lock, max_depth=3):
    found_domains = []  # Store found subdomains for this thread
    queue = Queue()
    queue.put(domain)  # Start with the initial domain

    depth = 0
    while not queue.empty() and depth < max_depth:
        depth += 1
        current_domain = queue.get()  # Get a subdomain to fuzz
        print(f"[*] Fuzzing subdomains for: {current_domain}")

        for sub in subdomains:
            # Create new subdomain by appending sub to the current domain
            new_domain = f"{sub}.{current_domain}"
            try:
                result = check_subdomain(new_domain)
                if result:  # If the subdomain resolves
                    found_domains.append(result)
                    queue.put(new_domain)  # Continue fuzzing this new subdomain
            except:
                None

        # Optional delay to avoid rate-limiting or overloading the DNS resolver
        time.sleep(0.1)

    # Lock to safely add results to the shared list (thread-safe)
    with result_lock:
        return found_domains

# Main function to handle multi-threading and process root domains
def fuzz_subdomains(root_file, sub_file, output_file=None, max_depth=3):
    # Read root domains from the root_file
    with open(root_file, 'r') as file:
        root_domains = [line.strip() for line in file.readlines()]

    # Read subdomains from the sub_file
    with open(sub_file, 'r') as file:
        subdomains = [line.strip() for line in file.readlines()]

    found_domains = []  # List to store found subdomains
    result_lock = threading.Lock()  # Lock for thread-safe operations on found_domains

    # Using ThreadPoolExecutor for multi-threading
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:  # Adjust max_workers based on system capabilities
        futures = []
        
        # Loop over each root domain and submit fuzzing tasks
        for root_domain in root_domains:
            print(f"[*] Fuzzing root domain: {root_domain}")
            futures.append(executor.submit(fuzz_subdomains_for_domain, root_domain, subdomains, result_lock, max_depth))

        # Collect results from all threads
        all_found_domains = []
        for future in concurrent.futures.as_completed(futures):
            all_found_domains.extend(future.result())  # Combine the results from each thread

    # Optionally write the found domains to an output file
    if output_file:
        with open(output_file, 'w') as file:
            for domain in all_found_domains:
                file.write(f"{domain}\n")
        print(f"[*] Results saved to {output_file}")

    return all_found_domains

# Argument parsing to handle command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Fuzz subdomains recursively")
    parser.add_argument("-r", "--roots", required=True, help="File containing the list of root domains")
    parser.add_argument("-s", "--subdomains", required=True, help="File containing the list of subdomains to fuzz")
    parser.add_argument("-o", "--output", help="Optional file to save the found subdomains")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Maximum depth for subdomain fuzzing (default: 3)")
    
    return parser.parse_args()

# Example usage
if __name__ == "__main__":
    args = parse_args()  # Parse the command-line arguments

    # Run the fuzzing process with the arguments provided by the user
    found = fuzz_subdomains(args.roots, args.subdomains, args.output, args.depth)
    print(f"[*] Found {len(found)} valid subdomains.")
