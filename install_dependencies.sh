wget https://tls.mbed.org/download/mbedtls-2.7.0-apache.tgz
tar xf mbedtls-2.7.0-apache.tgz
cd mbedtls-2.7.0
make
sudo make install
cd ..
rm -rf mbedtls*
