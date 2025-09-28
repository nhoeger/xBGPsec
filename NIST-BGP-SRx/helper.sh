#!/bin/bash
# Little Install Script to get it all started 
sudo apt install gcc libconfig-dev libssl-dev uthash-dev build-essential automake libreadline-dev m4 perl autoconf
sudo apt install -y build-essential automake autoconf libtool pkg-config m4 libconfig-dev libssl-dev uthash-dev libreadline-dev
sudo ln -s /usr/bin/aclocal /usr/bin/aclocal-1.16
sudo ln -s /usr/bin/automake /usr/bin/automake-1.16
sudo ./buildBGP-SRx.sh SRxSnP -A
cd local-6.3.3/bin
sed -i 's|library_name = "../../../../../../../lib64/srx/libSRxBGPSecOpenSSL.so";|library_name = "../lib64/srx/libSRxBGPSecOpenSSL.so";|' srxcryptoapi.conf
echo "Done"  