# electrum-radiocoin-4.1.4-current
electrum-radiocoin-4.1.4-current

10:25 AM UTC
i fixed the endless loop in electrum-radiocoin
if you run it as docker do a "docker pull"
if python reget the github repo and rebuild



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

docker run -it -d --net host -e "DISPLAY=${DISPLAY:-:0.0}" -v /tmp/.X11-unix:/tmp/.X11-unix c4pt/radiocoin-4.1.4-electrum bash
```
