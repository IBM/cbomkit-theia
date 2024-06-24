#!/bin/bash

# Navigate to the script directory
cd "$(dirname "$0")"

# Find all testdata directories
for dir in testdata/*; do
    if [ -d "$dir" ]; then
        # Assuming the input and output structure is consistent across test cases
        input="$dir/in/bom.json"
        dockerfile="$dir/image/Dockerfile"
        output="$dir/out/bom.json"

        # Check if input and Dockerfile exist
        if [ -f "$input" ] && [ -f "$dockerfile" ]; then
            echo "Regenerating output for test case in $dir"
            go run cics.go image build -b "$input" "$dockerfile" > "$output"
        else
            echo "Input or Dockerfile missing in $dir, skipping..."
        fi
    fi
done