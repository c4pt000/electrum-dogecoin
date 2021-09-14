regarding "electrum clients for radiocoin and dogecoin"

# 09-14-2021
* only use radiocoin-qt or radiocoind for now (avoid electrum-radiocoin , electrum-dogecoin still need to iron out bugs)

market orders are live @ https://github.com/c4pt000/radiox-exchange and exbitron.com for Radiocoin (RADC) to trade for DOGE, LTC, BTC



# native fix for conflict when both dogecoin and radiocoin are installed (since they both share the same executable as a conflict, since they are both a working rush job)
```
sudo cp -rf electrum-radiocoin /usr/bin/

/usr/bin/electrum-radiocoin/run_electrum 


add ^ to launcher

  ->       /usr/bin/electrum-radiocoin/run_electrum 
```

requires xhost as
```
xhost SI:localuser:root
```
```
docker run -it -d -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix c4pt/electrum-dogecoin-fbal


docker exec -it <docker_vm> bash
```
# * 07-30-2021 (required for don't formatting in console , cleaner look and feel)
```
yum install google*fonts 
or 
apt install google*fonts
``` 

# decimal floating errors possibly fixed (I have no dogecoin at the moment to test this)


![s1](https://raw.githubusercontent.com/c4pt000/electrum-dogecoin/main/electrum-dogecoin-about.png)
<br>

![s1](https://raw.githubusercontent.com/c4pt000/electrum-dogecoin/main/dogecoin-electrum.png)

<br>
<br>
<br>
<br>
<br>



# use at your risk floating decimal issues, (for stability use dogecoin-qt)

<h3>you've been warned continue at your own risk</h3>

* there are floating decimal issues, mostly the address tab in the main window never lies but it can get stuck,
* the history tab can be inaccurate, also sending maximum with the send window can be stuck,
* but import private key balance works to resolve stuck transactions or floating errors,
* right clicking to export an address balance to  import into a stable desktop-qt balance and checking the explorer can fix issues ( I was able to recover a 1.3 Billion balance transaction send from a floating point error 
* the video posted here is kind of confusing i guess for some, its meant as a panic resource to recover funds, 
* same here as dogecoin-electrum 

( a side note of sarcasm the code for electrum sat for years with developers all over the world, even elon musk boasts how great dogecoin can be with contracts the first step to finish a plate of dinner is to make the convenice of allowing the end user to sync a dogecoin wallet quickly instead of waiting constantly for dogecoin-qt to sync for a few hours or few days ) 

* I dont have money to really test these wallets except for dogecoin 

(I prefer to use actual crypto instead of test net funds, whats living on the edge anyway)

![s1](https://github.com/c4pt000/electrum-dogecoin/blob/main/floating.gif?raw=true)


# electrum-dogecoin-4.0.1 for electrum-dogecoin

https://github.com/c4pt000/electrum-dogecoin

* based off of electrum-nmc


# for server https://github.com/c4pt000/electrumx-dogecoin-server-dogecoin-4.1.4
# for DOGECOIN https://github.com/c4pt000/electrum-dogecoin

for dogecoin-electrum
https://github.com/c4pt000/electrum-wallet-doge

<br>
<br>
<br>
<br>
<br>
win10 release

https://github.com/c4pt000/electrum-dogecoin/releases/tag/win10


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
 sh install-dogecoin-electrum.sh 
```

 * todo hardcode  a minimum of 1.00 DOGE fee to send (with electrum)

# dont use with docker
* wont send a transaction while running from the docker guest (even with --net host)

* 07-06-2021
# PAPER wallet import works with dogecoin-electrum-4.1.4
![s1](https://raw.githubusercontent.com/c4pt000/dogecoin/master/just-the-right-QR-code-ignore-the-left.png)
# leave random deposit address and just import the QR on the right side of the crypto-currency bill (with the camera logo icon) 
* requires "pip3 install python-zbar" ? and uvcvideo and web cam support
* set default camera in "General" Preferences
![s1](https://raw.githubusercontent.com/c4pt000/dogecoin/master/electrum-import-paper-QR-radiodollar.png)
![s1](https://raw.githubusercontent.com/c4pt000/dogecoin/master/radio-electrum-4.1.4.paper-sweep.png)

# working
SAVE YOUR WALLET SEED TO RESTORE A BACKUP OF YOUR WALLET
(WITHOUT COMMITTING A DOCKER IMAGE TO A NEW WRITTEN IMAGE YOU WILL, LOSE ALL YOUR DATA WITHIN A DOCKER IMAGE!)

![s1](https://github.com/c4pt000/dogecoin/releases/download/electrum-wallet/electrum--dogecoin-sign-broadcast.png)
![s1](https://github.com/c4pt000/dogecoin/releases/download/electrum-wallet/electrum-4.1.4-dogecoin-send-amount.png)
![s1](https://github.com/c4pt000/dogecoin/releases/download/electrum-wallet/electrum-finalize-transaction.png)
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
