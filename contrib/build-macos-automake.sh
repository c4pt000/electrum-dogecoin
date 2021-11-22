cd autoconf-2.69			
./configure --prefix=/usr/local
make -j24 
make -j24 install
cd ..
cd automake-1.15
./configure --prefix=/usr/local
make -j24 
make -j24 install
cd ..
cd libtool-2.4.6
./configure --prefix=/usr/local
make -j24 
make -j24 install
cd ..
