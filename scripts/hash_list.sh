#!/bin/bash

# Check if directory is provided as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <directory>"
  exit 1
fi

DIRECTORY=$1

# Verify if the provided argument is a valid directory
if [ ! -d "$DIRECTORY" ]; then
  echo "Error: $DIRECTORY is not a valid directory."
  exit 1
fi

# List all files in the directory and compute their SHA256 hashes
find "$DIRECTORY" -type f -exec sha256sum {} \;
