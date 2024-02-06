# Network-Wide Rule Orchestrator

This project...

## **Table of Contents**
- [Installation process](#installation-process)
- [Repository structure](#repository-structure)
- [Replicating the experiments](#replicating-the-experiments)
- [Obtaining the baseline alerts](#obtaining-the-baseline-alerts)
- [Evaluating new topologies](#evaluating-new-topologies)

## Installation process

### 1. Install vagrant and VirtualBox

- [Vagrant](https://developer.hashicorp.com/vagrant/install)

- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

### 2. Build the P4 virtual machine

Clone the oficial repository:

```
git clone https://github.com/p4lang/tutorials.git
```

```
cd tutorial/vm-ubuntu-20.04
```
Run the following command:

```
vagrant up
```

### 3. Adjust the P4 VM settings

Turn off the machine, and extend the number of cores and memory size so it does not crash during the experiments.

For the experimnets we used a DELL server with a big amount of cores and memory. For the P4 VM we dfined:
- 22 vCPU cores
- 146 GB of memory

We did not experiment with smaller configuration values.

### 4. Log into the machine and clone this repository

```
sudo apt update && cd Documents
```

```
git clone  https://github.com/HenriqueBBrum/Network-Wide-Rule-Orchestrator.git && cd Network-Wide-Rule-Orchestrator
```

### 5. Download the CIC-IDS-2017 PCAP files and create a shared folder with the guest system



To dowload them, go to [this link](https://www.unb.ca/cic/datasets/ids-2017.html), and scroll down to the end of the page. Click the `Download this dataset` and fill in the required information. Finally, enter the `CIC-IDS-2017` directory, then the `PCAPs` directory, and download the PCAP for each day of the week.

Save them into your host machine in one folder. For the guest folder, it must be named `CICIDS2017-PCAPS` and placed at the same level as this repo's folder. The image below illustrates this:


For more information on how to create shared folders with VirtualBox, follow these links:
- [How to Create and Access a Shared Folder in VirtualBox](https://www.makeuseof.com/how-to-create-virtualbox-shared-folder-access/)
- [How to create shared folder for virtual machine on VirtualBox](https://pureinfotech.com/create-shared-folder-virtual-machine-virtualbox/)




### 6. Install the dependencies

The last step is to run the below command to automatically install all required dependencies and configure the enviroment:

```
./install_dependencies.sh
```

> :warning: This script takes a long time to finish, so be patitent.

The packages and tools installed are the following:
- tcpreplay
- matplotlib and networkx (Python)
- BMv2 (for custom high performance)
- Snort3


After this process ends, the enviroment is configured and ready to run the experiments. 

## Repository structure

```
├── baseline_alerts/
├── snort/
├── src/
├── testing/
├── utils/
├── .gitignore
├── install_dependencies.sh
├── README.md
```

- **`baseline_alerts/`**: The images used in the README file;

- **`snort/`**: Contains default configuration files shared across the application;
  - **`default.json`**: Default configuration file;
  - **`default.json`**: Default configuration file;
  - **`default.json`**: Default configuration file;


- **`src/`**: Handles application logic and routes for various functionalities;
	- **`default.json`**: Default configuration file;
	- **`default.json`**: Default configuration file;
	- **`default.json`**: Default configuration file;
	- **`default.json`**: Default configuration file;

- **`testing/`**: Handles database-related functionalities by connecting to MongoDB using Mongoose;
	- **`default.json`**: Default configuration file;
	- **`default.json`**: Default configuration file;
	- **`default.json`**: Default configuration file;

- **`utils/`**: Folder containing Python files that interact with Mininet and the P4Runtime;
	- **`default.json`**: Default configuration file;
	- **`default.json`**: Default configuration file;

- **`.gitignore`**: Files for git to ignore;

- **`/install_dependencies.sh`**: Script used in the installation processes to install depedencies and configure the environment

- **`/README.md`**: README file with this project's documentation


## Replicating the experiments

There are two set of experiments to replicate: the data plane parameters evaluation[](), and the final evaluation. The first evaluates different data plane configurations while the latter evalaute the network-wide distribution algorithms in two topology scenarios with diffferent memoery avialbilty in the switches.


### Data plane parameters evaluation

uncomment    switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_json)
			 print("Installed P4 Program using SetForwardingPipelineConfig on switch "+switch_id)

uncomment         standard_metadata.egress_spec = DEFAULT_PORT;
comment ipv4_lpm.apply();

Pass the fullpath to the output folder


### Final evaluation experiments


### Run individual experiments


## Obtaining the baseline alerts

command to test baseline slerts by snort


snort -c snort.lua --rule-ath ../rule/path -R pcap_file.pcap -A alert_json --lua "alert_json = {file = true}"


## Evaluating new topologies
