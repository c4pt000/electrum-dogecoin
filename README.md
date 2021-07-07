# electrum-radiocoin-4.1.4-current

fedora 34
will not send a TX while running from docker use the installer natively instead 
```
docker run -it --net host -d -e "DISPLAY=${DISPLAY:-:0.0}" -v /tmp/.X11-unix:/tmp/.X11-unix fedora:34

# (fedora 34)

cd /opt
 yum install git nano wget -y
 git clone https://github.com/c4pt000/electrum-radiocoin-4.0.0b-current
 cd electrum-radiocoin-4.0.0b-current/
 sh install-radiocoin-electrum.sh 
```

 * has to be a minimum of 1.00 RADC fee to send (with electrum)

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
