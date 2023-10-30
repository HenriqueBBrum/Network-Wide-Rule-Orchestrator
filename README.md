# Network-Wide-Rule-Orchestrator


How to execute:


make clean && make


then run the mycontroller.py to build the switch configuration

python3 mycontroller.py --network_info etc/simple_linear_scenario/network_info.json --table_entries p4snort.config


commands to run in each host


hinternet:

	tcpreplay -i eth0 -p100 Monday...pcap

hsnort

	snort -c ../snort/configuration/snort.lua --rule-path ../snort/rules/snort-community -A alert_json --lua "alert_json = {file = true}" -l ../snort/logs -i eth0
	snort -c ../snort/configuration/snort.lua --rule-path ../snort/rules/snort-community -A alert_json --lua "alert_json = {file = true}" -l ../snort/logs -i hsnort-eth1
	snort -c ../snort/configuration/snort.lua --rule-path ../snort/rules/snort-community -A alert_json --lua "alert_json = {file = true}" -l ../snort/logs -i hsnort-eth2 --lua > stdout_output.txt