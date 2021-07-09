#!/bin/bash 
echo "Fedora 34 install for electrum-radiocoin"
yum install python3-pip git libsecp256k1-devel.x86_64 libsecp256k1 mesa* \
nano qrencode-devel qt5-qtbase-devel.x86_64 qt-devel qt4-devel wget -y

	cd /opt/

	git clone https://github.com/c4pt000/electrum-radiocoin-4.0.0b-current
	cd electrum-radiocoin-4.0.0b-current/

	python3 -m pip install cryptography PyQt5
	python3 -m pip install .
	./run_electrum_radc 
