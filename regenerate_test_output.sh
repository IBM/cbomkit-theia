#!/bin/bash

# Navigate to the script directory
cd "$(dirname "$0")"

# Find all testdata directories
for dir in testdata/*; do
    if [ -d "$dir" ]; then
        # Assuming the input and output structure is consistent across test cases
        input="$dir/in/bom.json"
        dockerfile="$dir/image/Dockerfile"
        dirinput="$dir/dir"
        output="$dir/out/bom.json"

        # Check if input and Dockerfile exist
        if [ -f "$input" ]; then
            echo "Regenerating output for test case in $dir"
            
            if [ -d "$dir/dir" ]; then
                go run cics.go dir -b "$input" "$dirinput" > "$output"
            elif [ -d "$dir/image" ]; then
                if [ ! -f "$dockerfile" ]; then
                    echo "Dockerfile not found in $dir/image, skipping..."
                    continue
                fi
                go run cics.go image build -b "$input" "$dockerfile" > "$output"
            else
                echo "Directory 'dir' or 'image' not found in $dir, skipping..."
            fi
        else
            echo "Input or Dockerfile missing in $dir, skipping..."
        fi
    fi
done