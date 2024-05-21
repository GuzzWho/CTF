#!/usr/bin/env python3
from Crypto.PublicKey import ECC
from base64 import b64decode, b64encode
from ast import literal_eval
from termcolor import colored
import sys

DEBUG = 1 if sys.argv[-1].lower() == "debug"  else 0

def find_all_common_substrings(s1, s2, min_length=4):
    common_substrings = set()
    len_s1 = len(s1)
    len_s2 = len(s2)
    
    for length in range(min_length, len_s1 + 1):
        for i in range(len_s1 - length + 1):
            substring = s1[i:i + length]
            if substring in s2:
                common_substrings.add(substring)
                
    return common_substrings

b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

if len(sys.argv) < 3 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
    print("Usage: python3 recovery.py <public_key_file> <corrupted_private_key_file>")
    sys.exit()

public_file_path = sys.argv[1]
private_file_path = sys.argv[2]

# Read the public and private keys
with open(f'{public_file_path}', 'r') as public_key_file:    
    public_key_data = public_key_file.read()
    hex_public = b64decode(public_key_data.split(' ')[1]).hex()
    pubkey_len = len(hex_public)
    public_ecc_key = ECC.import_key(public_key_data)

with open(f'{private_file_path}', 'r') as private_key_file:
    if DEBUG:
        print("Private key:", hex(ECC.import_key(open(f'{private_file_path}').read()).d)[2:])
    private_key_data = private_key_file.readlines()
    if not private_key_data[0].startswith('-----BEGIN OPENSSH PRIVATE KEY') and not DEBUG:
        sys.exit("Unsupported private key format")
    
    corrected_private_key_lines = []
    for line in private_key_data[1:-1]:
        if len(line.strip()) != 70:
            line = line.strip() + '/' * (70 - len(line.strip()))
        corrected_line = ''.join(c if c in b64_chars else '/' for c in line.strip().strip('='))
        corrected_private_key_lines.append(corrected_line)
    
    hex_private = b64decode(''.join(corrected_private_key_lines)+'==').hex()
    
        
            
# Generate the ECC key for the NIST P-256 curve
curve = public_ecc_key.curve
curve = ECC._curves[curve]
point_x = int(public_ecc_key.pointQ.x)
point_y = int(public_ecc_key.pointQ.y)

# Print the public key information
print("Public key: ", (point_x, point_y))
print("curve: ", curve.name)
print("generator: ", (curve.Gx, curve.Gy))
print("order: ", curve.order)  
print("modulus: ", curve.p)
print("hex_public:")
print(hex_public)


# Find common substrings between the public and private keys
min_length = 8  # Adjust the minimum length as needed
common_substrings = find_all_common_substrings(hex_public, hex_private, min_length)
sorted_substrings = sorted(common_substrings, key=len, reverse=True)

color_indices = []
for substring in sorted_substrings:
    index = 0
    while index < len(hex_private):
        start_index = hex_private.find(substring, index)
        if start_index == -1:
            break
        end_index = start_index + len(substring)
        if len(color_indices) == 0:
            color_indices.append((start_index, end_index))
        else:
            flag = 1
            for i in range(len(color_indices)):
                if start_index >= color_indices[i][0] and start_index <= color_indices[i][1] and end_index >= color_indices[i][0] and end_index <= color_indices[i][1]:
                    flag = 0
                    break
            if flag:
                color_indices.append((start_index, end_index))
                     
        index = end_index

# Handle coloring of public and private info for better visualization
color_indices = sorted(color_indices, key=lambda x: x[0])
highlight_indices = []
for x in range(len(color_indices)):
    start_index = hex_public.find(hex_private[color_indices[x][0]:color_indices[x][1]])
    end_index =  start_index + len(hex_private[color_indices[x][0]:color_indices[x][1]])
    start_index = color_indices[x][0] - start_index
    end_index = color_indices[x][1] + (pubkey_len - end_index)
    highlight_indices.append((start_index, end_index))

highlight_indices = sorted(list(set(highlight_indices)), key=lambda x: x[0])
prev = 0
colored_hex_private = ""
for indices in highlight_indices:
    colored_hex_private += hex_private[prev:indices[0]] + colored(hex_private[indices[0]:indices[1]], 'red')
    prev = indices[1]
colored_hex_private += colored(hex_private[prev:],'green')

print("hex_private:")
print(colored_hex_private)

# Standard length of a private key in ecdsa-sha2-nistp256
# Adjust parameters here
hex_delimiter = "0000002100"
len_delimiter = len(hex_delimiter)
privkey_len = 64  

print("public keys:")
for x in highlight_indices:
    print(hex_private[x[0]:x[1]])
print("private keys:")
start_private = highlight_indices[-1][1]+len_delimiter
print(hex_private[start_private:start_private+privkey_len])

