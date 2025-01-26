import hashlib
import base58
from Crypto.Hash import RIPEMD160
from multiprocessing import Pool, cpu_count
import os
from termcolor import cprint

def welcome_message():
    cprint("************************************************", 'yellow', attrs=['bold'])
    cprint("*            CRYPTOGRAPHYTUBE Bitcoin          *", 'yellow', attrs=['bold'])
    cprint("*      Vulnerability Check for Bitcoin Address  *", 'yellow', attrs=['bold'])
    cprint("************************************************", 'yellow', attrs=['bold'])
    cprint("\n\n", 'white')

def validate_script_injection(address):
    decoded_address = base58.b58decode(address)
    if len(decoded_address) != 25:
        return False, "Invalid address length."

    version_byte = decoded_address[0:1]
    hash160 = decoded_address[1:21]
    checksum = decoded_address[21:25]

    if '0' in address or 'O' in address or address.count('1') > 10:
        return False, "Suspicious characters detected (0, O, or many 1's)."

    if not verify_checksum(version_byte, hash160, checksum):
        return False, "Invalid checksum."

    return True, ""

def verify_checksum(version, hash160, checksum):
    versioned_payload = version + hash160
    sha256_1 = hashlib.sha256(versioned_payload).digest()
    sha256_2 = hashlib.sha256(sha256_1).digest()
    computed_checksum = sha256_2[:4]

    return computed_checksum == checksum

def extract_public_key(address):
    decoded_address = base58.b58decode(address)
    hash160 = decoded_address[1:21]
    return hash160.hex()

def address_from_public_key(public_key_hex):
    pubkey_bytes = bytes.fromhex(public_key_hex)
    hash160 = RIPEMD160.new(hashlib.sha256(pubkey_bytes).digest()).digest()
    
    version = b'\x00'
    checksum = hashlib.sha256(hashlib.sha256(version + hash160).digest()).digest()[:4]
    
    address = base58.b58encode(version + hash160 + checksum).decode()
    return address

def process_address(address):
    """
    Process a single address and return the suspicious result and reason.
    """
    is_valid, reason = validate_script_injection(address)
    if not is_valid:
        public_key_hash = extract_public_key(address)
        generated_address = address_from_public_key(public_key_hash)
        return (address, reason, public_key_hash, generated_address)
    return None

def check_addresses_in_file(file_path):
    """
    Process all addresses in the file and write suspicious addresses to found.txt.
    """
    total_addresses = sum(1 for line in open(file_path))  # Count total lines in file
    cprint(f"Total addresses to check: {total_addresses}", 'cyan')

    with open(file_path, 'r') as file, open('found.txt', 'w') as found_file:
        # Read all addresses from file
        addresses = [line.strip() for line in file if line.strip()]

        # Process addresses in parallel using multiprocessing
        with Pool(processes=cpu_count()) as pool:
            results = pool.map(process_address, addresses)

            for result in results:
                if result:
                    address, reason, public_key_hash, generated_address = result
                    found_file.write(f"Suspicious address found: {address}\n")
                    found_file.write(f"Reason: {reason}\n")
                    found_file.write(f"Public Key Hash: {public_key_hash}\n")
                    found_file.write(f"Generated Address: {generated_address}\n")
                    found_file.write("\n")
                    cprint(f"Suspicious address found: {address}", 'red')

if __name__ == "__main__":
    welcome_message()
    btc_file_path = input("Enter the path to the BTC addresses text file: ").strip()
    check_addresses_in_file(btc_file_path)
    cprint("\n\nVulnerability checking completed. Found suspicious addresses in 'found.txt'.", 'green')
