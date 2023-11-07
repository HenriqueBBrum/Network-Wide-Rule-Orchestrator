# install depedencies

sudo apt tcpreplay

sudon pip install matplotlib
sudo pip install networkx

dowload behaviorual model
./autogen.#!/bin/sh
#./configure 'CXXFLAGS=-g -O3' 'CFLAGS=-g -O3'  --with-pi --with-thrift --disable-logging-macros --disable-elogger
make && sudo make install && sudo ldconfig

cd targets/simple_switch_grpc
./configure --with-thrift 'CXXFLAGS=-O0 -g'
make && sudo make install && sudo ldconfig


dowload cicids2017 files
