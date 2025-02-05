#!/bin/bash

set -eux -o pipefail

# Get the directory that this script file is in
THIS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

cd "$THIS_DIR"

shopt -s extglob # Enable negative globbing
cp static/!(*.go) public
go build -o functions/gmailsig .
