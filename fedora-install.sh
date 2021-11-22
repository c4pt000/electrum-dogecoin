#!/bin/bash 
echo "Fedora 34 install for electrum-radiocoin"
yum install python3-pip git libsecp256k1-devel.x86_64 libsecp256k1 mesa* zbar \
nano qrencode-devel qt5-qtbase-devel.x86_64 qt-devel qt4-devel wget google*fonts -y

	cd /opt/

	git clone https://github.com/c4pt000/electrum-radiocoin
	cd electrum-radiocoin

	python3 -m pip install cryptography PyQt5 ecdsa
	python3 -m pip install .
	echo "running electrum-radiocoin"
	echo "./run_electrum"
	echo ""
	echo "requires port 50002 open for connectivity"
	echo "for electrum-radiocoin users close electrum-RADC for radiocoin run /opt/electrum-radiocoin/run_electrum for electurm-radiocoin instead"
	./run_electrum &
