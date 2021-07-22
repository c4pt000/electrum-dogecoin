# electrum-dogecoin-4.0.1 

# seems like its working


todo:
balance bug in "history" addresses tab shows accurate balance
export privkey from wallet to transfer funds out of wallet in case of a send tx balance error
<br>
<br>
addresses tab reports current correct balance of wallet
<br>
<br>
balance bug in "history" tab, (doesnt effect "addresses" tab)
<br>

![s1](https://raw.githubusercontent.com/c4pt000/electrum-radiocoin/main/balance-bug-check-addresses-tab.png)


for the older dogecoin 2.2.1 original client 
https://github.com/c4pt000/electrum-wallet-doge

![s1](https://raw.githubusercontent.com/c4pt000/electrum-dogecoin/main/electrum-receive.png)
![s1](https://raw.githubusercontent.com/c4pt000/electrum-dogecoin/main/electrum-receive.png)

protocol must be set 1.4 (instead of 0.9 or less than 1.4)
2.2.1 client https://raw.githubusercontent.com/c4pt000/electrum-wallet-doge/master/lib/version.py
in 4.0.1 its part of servers.json and version.py

edit servers in wallet for new nodes or server creation 

# 4.0.1 electrum-dogecoin servers.json
https://raw.githubusercontent.com/c4pt000/electrum-dogecoin/main/electrum_nmc/electrum/servers.json

electrum_nmc/electrum/servers.json

2.2.1 electrum-wallet-doge lib/network.py
https://raw.githubusercontent.com/c4pt000/electrum-wallet-doge/master/lib/network.py

lib/network.py



* based off of electrum-nmc

for server https://github.com/c4pt000/electrumx-dogecoin-server-radiocoin-4.1.4
<br>
for radiocoin-electrum https://github.com/c4pt000/electrum-radiocoin

<br>
<br>

https://raw.githubusercontent.com/c4pt000/electrum-dogecoin/main/fedora-install.sh
<br>
https://raw.githubusercontent.com/c4pt000/electrum-dogecoin/main/ubuntu-install.sh
<br>
https://github.com/c4pt000/electrum-dogecoin/releases/download/win10/electrum-dogecoin-4.0.1-setup.exe

fedora 34
<br>
will not send a TX while running from docker use the installer natively instead 
```
docker run -it --net host -d -e "DISPLAY=${DISPLAY:-:0.0}" -v /tmp/.X11-unix:/tmp/.X11-unix fedora:34

# (fedora 34)

cd /opt
 yum install git nano wget -y
 git clone https://github.com/c4pt000/electrum-dogecoin
 cd electrum-dogecoin
 sh fedora-install.sh
```




# original notes radiocoin-electrum "errata" 

 * todo hardcode  a minimum of 1.00 RADC fee to send (with electrum)

# dont use with docker
* wont send a transaction while running from the docker guest (even with --net host)

* 07-06-2021
# PAPER wallet import works with radiocoin-electrum-4.1.4
![s1](https://raw.githubusercontent.com/c4pt000/radiocoin/master/just-the-right-QR-code-ignore-the-left.png)
# leave random deposit address and just import the QR on the right side of the crypto-currency bill (with the camera logo icon) 
* requires "pip3 install python-zbar" ? and uvcvideo and web cam support
* set default camera in "General" Preferences
![s1](https://raw.githubusercontent.com/c4pt000/radiocoin/master/electrum-import-paper-QR-radiodollar.png)
![s1](https://raw.githubusercontent.com/c4pt000/radiocoin/master/radio-electrum-4.1.4.paper-sweep.png)

# working
SAVE YOUR WALLET SEED TO RESTORE A BACKUP OF YOUR WALLET
(WITHOUT COMMITTING A DOCKER IMAGE TO A NEW WRITTEN IMAGE YOU WILL, LOSE ALL YOUR DATA WITHIN A DOCKER IMAGE!)

![s1](https://github.com/c4pt000/radiocoin/releases/download/electrum-wallet/electrum--radiocoin-sign-broadcast.png)
![s1](https://github.com/c4pt000/radiocoin/releases/download/electrum-wallet/electrum-4.1.4-radiocoin-send-amount.png)
![s1](https://github.com/c4pt000/radiocoin/releases/download/electrum-wallet/electrum-finalize-transaction.png)
```
wget https://raw.githubusercontent.com/c4pt000/Docker-fedora-34-nested-docker-OpenCore-ARM64/main/xhost-gen
chmod +x xhost-gen
#check if your system supports xhost as root
xhost
#if not install xhost
./xhost-gen
#as root 
echo "xhost SI:localuser:root" >> /root/.bashrc
source /root/.bashrc

```
