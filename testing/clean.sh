cd ../src
make clean

cd ../experiments_output
rm -r *

rm ../snort/logs/eth0/*
rm ../snort/logs/hsnort-eth1/*
rm ../snort/logs/hsnort-eth2/*
