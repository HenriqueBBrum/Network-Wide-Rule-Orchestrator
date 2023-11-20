# Network-Wide-Rule-Orchestrator

## Installation Process

### 1. Install vagrant and VirtualBox, and build the P4 virtual machine

git clone https://github.com/p4lang/tutorials.git
cd tutorial/vm-ubuntu-20.04
vagrant up


### 2. Turn of the machine and extend the number of cores (4cores) and memory size (4GB)

### 3. Download the CIDIDS-2017 files and create a shared folder with the guest system


The guest folder should be named CICIDS2017-PCAPS and placed at the same level as this repo's folder. The image below illustrates this:


Follow this guide to understand how to create shared folders with VirtualBox 

### 4. Log into the machine and clone this repository 

```
sudo apt update
```

```
cd Documents
```

```
git clone  https://github.com/HenriqueBBrum/Network-Wide-Rule-Orchestrator.git
```

```
cd Network-Wide-Rule-Orchestrator
```

### 5. Install the dependencies

The installed packages include:
	- tcpreplay
	- Matplotlib and networkx (Python)
	- BMv2 (for custom high performance)
	- Snort3


```
./install_dependencies.sh
```


## Running an experiment

```
cd testing && ./run_experiments linear ../experiments_output
```



commands to run in each host

hsnort

	snort -c ../snort/configuration/snort.lua --rule-path ../snort/rules/snort-community -A alert_json --lua "alert_json = {file = true}" -l ../snort/logs -i eth0
	snort -c ../snort/configuration/snort.lua --rule-path ../snort/rules/snort-community -A alert_json --lua "alert_json = {file = true}" -l ../snort/logs -i hsnort-eth1
	snort -c ../snort/configuration/snort.lua --rule-path ../snort/rules/snort-community -A alert_json --lua "alert_json = {file = true}" -l ../snort/logs -i hsnort-eth2 --lua > stdout_output.txt


hinternet:

	tcpreplay -i eth0 -p100 ../../CICIDS2017-PCAPS/Monday...pcap


command to test baseline slerts by snort


snort -c snort.lua --rule-ath ../rule/path -R pcap_file.pcap -A alert_json --lua "alert_json = {file = true}" 