#!/bin/bash


parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )


topology=$1
output_folder=$2



# MAX_PACKETS = 10;
# TIME_THRESHOLD = 10;
# COUNT_MIN_SIZE = 256;

pcaps_folder=