#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import ipaddress

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_ip(ip):
    """Check if the provided IP address is valid."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_bluekeep_vuln(target_ip):
    """Check if the target IP is vulnerable to BlueKeep."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target_ip, 3389))
        pre_auth_pkt = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        sock.send(pre_auth_pkt)
        data = sock.recv(1024)
        sock.close()
        if b"\x03\x00\x00\x0c" in data:
            return f"[+] {target_ip} is likely VULNERABLE to BlueKeep!"
        else:
            return f"[-] {target_ip} is likely patched :("
    except (socket.timeout, socket.error) as e:
        return f"[-] {target_ip} is either not up or not vulnerable ({str(e)})"
    finally:
        sock.close()

def scan_ips(targets):
    """Scan a list of target IP addresses for BlueKeep vulnerability."""
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_bluekeep_vuln, target): target for target in targets}

        for future in as_completed(futures):
            logging.info(future.result())

def main():
    parser = argparse.ArgumentParser(description="Scan a list of target IP addresses for BlueKeep vulnerability")
    parser.add_argument("-t", "--targets", required=True, nargs='+', help="List of target IP addresses separated by space")
    args = parser.parse_args()

    # Validate the list of targets
    valid_targets = [ip for ip in args.targets if is_valid_ip(ip)]
    if not valid_targets:
        logging.error("No valid IP addresses provided.")
        return

    logging.info(f"Starting BlueKeep vulnerability scan on {len(valid_targets)} targets...")
    scan_ips(valid_targets)
    logging.info("Scan completed.")

if __name__ == "__main__":
    main()
