# 11-23-2021 working send / receive 
# 11-23-2021 (fixed server side , HAD no DOGE to test binance.us delay up to 5 days?)

# need to adjust main QR code workaround 
# todo -> remove ?time= date by unix epoch from address URI label
```
date +%s
```
![s1](https://github.com/c4pt000/electrum-dogecoin/releases/download/android/todo-remove-time-from-URI.gif)
# scan from QR icon (not QR window)
![s1](https://github.com/c4pt000/electrum-dogecoin/releases/download/android/scan-from-here.gif)

# for android -> see releases

# https://github.com/c4pt000/electrum-dogecoin/releases/tag/android

```
cd /usr/bin
wget https://github.com/c4pt000/electrum-uraniumx/releases/download/electrum-uraniumx/electrum-radiocoin.tar.gz
tar -xvf electrum-radiocoin.tar.gz
```


# macOS (requires python3 , xcode command line tools)
```
cd electrum-radiocoin
python3 -m pip install --upgrade pip
python3 -m pip install .
python3 -m pip install PyQt5
cd contrib
sh build-macos-automake.sh
sh make_libsecp256k1.sh
cd ..
./run_electrum
```
