#!/bin/bash
 apt-get update && \
 apt install git nano sudo wget python3 python3-pip python3-dev libsecp256k1-0 python3-pyqt5 google*fonts zbar -y
 cd /opt/
 git clone https://github.com/c4pt000/electrum-radiocoin
 cd electrum-radiocoin/
 python3 -m pip install cryptography
 python3 -m pip install . && ./run_electrum_radc 
	echo "for electrum-radiocoin users close electrum-RADC for radiocoin run /opt/electrum-radiocoin/run_electrum for electurm-radiocoin instead"
