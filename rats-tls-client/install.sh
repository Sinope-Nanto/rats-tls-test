cp /usr/local/lib/rats-tls/lib* lib/
mkdir build && cd build
cmake ..
make install
cd ..
rm -rf build
cp -r lib/ ../samples
cp client.sh ../samples