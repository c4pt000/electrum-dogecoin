# electrum-radiocoin-4.1.4-current
electrum-radiocoin-4.1.4-current

10:25 AM UTC
i fixed the endless loop in electrum-radiocoin
if you run it as docker do a "docker pull"
if python reget the github repo and rebuild
```
docker run -it --net host -d -e "DISPLAY=${DISPLAY:-:0.0}" -v /tmp/.X11-unix:/tmp/.X11-unix c4pt/radiocoin-4.1.4-electrum
```
