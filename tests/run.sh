#!/bin/sh
set -eu

# cd into the directory of this script
cd "$(dirname "$0")"

for t in abandon; do
    ( cd "$t" && ./run.sh )
done
