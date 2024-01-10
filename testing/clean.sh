#!/bin/bash
scriptdir="$(dirname "$0")"
cd "$scriptdir"

cd ../src
make clean

cd ../experiments_output
rm -r *

sudo rm -r ../snort/logs/*
