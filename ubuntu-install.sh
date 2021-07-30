#!/bin/bash
 apt-get update && \
 apt install git nano sudo wget python3 python3-pip python3-dev libsecp256k1-0 python3-pyqt5 zbar -y
 cd /opt/
 git clone https://github.com/c4pt000/electrum-dogecoin
 cd electrum-dogecoin/
 python3 -m pip install cryptography
 python3 -m pip install . && ./run_electrum_radc 
