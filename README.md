
```
see editing
for remote electrum servers
electrum-doge.conf.sample:server = 45.56.96.128:50101:t
lib/network.py:    '45.56.96.128':DEFAULT_PORTS,
electrum-doge.conf.sample:server = 45.56.96.128:50101:t
```

Electrum-DOGE - lightweight Dogecoin client

Licence: GNU GPL v3
Author: Electrum-DOGE contributors & Thomas Voegtlin
Language: Python
Homepage: https://electrum-doge.com


1. GETTING STARTED
------------------

To run Electrum from this directory, just do:

  ./electrum-doge

If you install Electrum on your system, you can run it from any
directory:

  sudo python setup.py install
  electrum-doge

2. HOW OFFICIAL PACKAGES ARE CREATED
------------------------------------

python mki18n.py
pyrcc4 icons.qrc -o gui/qt/icons_rc.py
python setup.py sdist --format=zip,gztar

On Mac OS X:

  # On port based installs
  sudo python setup-release.py py2app

  # On brew installs
  ARCHFLAGS="-arch i386 -arch x86_64" sudo python setup-release.py py2app --includes sip

  sudo hdiutil create -fs HFS+ -volname "Electrum-Doge" -srcfolder dist/Electrum-Doge.app dist/electrum-doge-VERSION-macosx.dmg


