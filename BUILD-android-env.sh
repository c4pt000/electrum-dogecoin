#!/bin/bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager     --add-repo     https://download.docker.com/linux/fedora/docker-ce.repo
 sudo dnf install docker-ce docker-ce-cli containerd.io -y
  systemctl start docker
  systemctl enable docker
    python -m pip install docutils pygments pypiwin32 
   python -m pip install Kivy
   pip3 install .[full]
    cd /opt
   git clone https://github.com/kivy/python-for-android
    cd python-for-android
   git remote add agilewalker https://github.com/agilewalker/python-for-android
   git fetch --all
   git checkout 93759f36ba45c7bbe0456a4b3e6788622924cbac
   git merge a2fb5ecbc09c4847adbcfd03c6b1ca62b3d09b8d
    cd /opt
    git clone https://github.com/kivy/buildozer
    cd buildozer
    sudo python3 setup.py install
    cd /opt/
    wget https://www.crystax.net/download/crystax-ndk-10.3.1-linux-x86_64.tar.xz
    pyrcc5 icons.qrc -o gui/qt/icons_rc.py
    pip install Pillow
echo '
build kivy atlas manually with::
    cd contrib/android/
    make theming
 '
echo '
load kivy style gui for testing
    ./run_electrum -g kivy
'
