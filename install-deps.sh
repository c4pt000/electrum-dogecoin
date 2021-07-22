yum install python2 gcc g++ -y
yum install RPMS/python2-pip-9.0.3-18.module_el8.4.0+642+1dc4fb01.noarch.rpm -y
python2 -m pip install .
yum install RPMS/python2-dbus-1.2.8-5.fc30.x86_64.rpm -y 
yum install RPMS/python2-pyqt4-sip-4.19.19-1.fc30.x86_64.rpm -y
yum install RPMS/PyQt4-4.12.3-6.fc30.x86_64.rpm -y
rpm -Uvh --force --nodeps RPMS/sip-4.19.19-1.fc30.x86_64.rpm 
yum install RPMS/python2-sip-devel-4.19.19-1.fc30.x86_64.rpm -y
yum install RPMS/PyQt4-devel-4.12.3-6.fc30.x86_64.rpm -y
pyrcc4 icons.qrc -o gui/qt/icons_rc.py
python2 -m pip install zbar-py
./electrum-doge 
