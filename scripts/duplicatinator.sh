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

# Create a temporary file to store hashes and associated file paths
TEMP_FILE=$(mktemp)

# Use find to process files in the directory recursively
find "$DIRECTORY" -type f -exec sha256sum {} \; > "$TEMP_FILE"

# Use awk to find and print duplicate hashes and their corresponding files
awk '
{
  count[$1]++;
  files[$1] = files[$1] ? files[$1] ORS $2 : $2;
}
END {
  for (hash in count) {
    if (count[hash] > 1) {
      print "Hash:", hash;
      print "Files:";
      print files[hash];
      print "";
    }
  }
}' "$TEMP_FILE"

# Remove the temporary file
rm "$TEMP_FILE"
