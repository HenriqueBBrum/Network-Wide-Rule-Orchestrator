#!/bin/bash

# Install depedencies

sudo apt install -y tcpreplay

sudo pip install networkx
sudo pip install matplotlib

# Download BMV2 to build the performance version

cd ../..

git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model/
/bin/bash install_deps.sh
sudo apt-get install -y libreadline-dev
/bin/bash autogen.sh
/bin/bash configure 'CXXFLAGS=-g -O3' 'CFLAGS=-g -O3'  --with-pi --with-thrift --disable-logging-macros --disable-elogger

make
sudo make install
sudo ldconfig

cd targets/simple_switch_grpc
/bin/bash configure --with-thrift 'CXXFLAGS=-O0 -g'
make
sudo make install
sudo ldconfig

# Install snort

mkdir ~/SNORT
cd ~/SNORT

sudo apt install build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev luajit hwloc libdnet-dev libdumbnet-dev bison flex liblzma-dev openssl \
 libssl-dev pkg-config libhwloc-dev cmake cpputest libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev \
 libunwind-dev libfl-dev -y


git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make
sudo make install


cd ../
wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.9.1/gperftools-2.9.1.tar.gz
tar xzf gperftools-2.9.1.tar.gz
cd gperftools-2.9.1/
./configure
make
sudo make install


cd..
wget https://github.com/snort3/snort3/archive/refs/heads/master.zip
unzip master.zip
cd snort3-master
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc

cd build
make
sudo make install
sudo ldconfig

# Dowload CIDIDS-2017 files

