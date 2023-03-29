# rats-tls-test
## Build Requirements
+ git
+ make & cmake
+ gcc
+ libssl-dev

## Compile & Install
git clone git@github.com:Sinope-Nanto/rats-tls-test.git  
cd rats-tls-test  
git submodule init  
git submodule update  
cd src  
mkdir build && cd build  
cmake ..  
sudo make install  

## Run Samples
cd rats-tls-test/rats-tls-client  
./install.sh  
cd ../rats-tls-server  
./install.sh  
cd ../samples  
./server.sh  
(another terminal)  
./client.sh  
