# electrum-dogecoin-2.2.1

requires docker and X11-xhost 


as root
```
docker run --net host -it -d -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix c4pt/electrum-doge-2.2.1
```

for xhost install
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
