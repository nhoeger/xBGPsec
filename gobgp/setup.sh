# Remove all running docker instances 
docker kill $(docker ps -q)

# Copy the router_config_files to /tmp
cd /home/nils/Dokumente/ASPA+/NIST-BGP-SRx

# Start the RPKI Server 
echo "add 10.0.0.0/8 9 7675" > ./rpkirtr_svr.conf
gnome-terminal --title="RPKI" -- bash -c "docker run --rm -it --name rpkirtr_server \
    -v $PWD/./rpkirtr_svr.conf:/usr/etc/rpkirtr_svr.conf \
    -p 323:323 \
    nist/bgp-srx \
    rpkirtr_svr -f /usr/etc/rpkirtr_svr.conf"
sleep 1

# Start the SRx-Server 
sed "s/localhost/$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' rpkirtr_server)/g" ./srx-server/src/server/srx_server.conf > /tmp/srx_server.conf
gnome-terminal --title="SRx-Server" -- bash -c "docker run --rm -it --name srx_server \
    -v /tmp/srx_server.conf:/usr/etc/srx_server.conf \
    -v $PWD/./examples/bgpsec-keys/:/usr/opt/bgp-srx-examples/bgpsec-keys \
    -p 17900:17900 -p 17901:17901 \
    nist/bgp-srx \
    srx_server -f /usr/etc/srx_server.conf"
sleep 1

# Start router instances 
gnome-terminal --title="GoBGP 1 - AS65004" -- bash -c "cd /home/nils/Dokumente/ASPA+/gobgp && docker run --name AS65004 --rm -it -v ./router_config_files/router_1.conf:/root/demo.conf gobgp"
# sleep 1
# gnome-terminal -- bash -c "docker run --name gobgp_router_2 --rm -it -v ./router_config_files/router_2.conf:/root/demo.conf gobgp"
sleep 1
gnome-terminal --title="GoBGP 3 - AS65006" -- bash -c "cd /home/nils/Dokumente/ASPA+/gobgp && docker run --name AS65006 --rm -it -v ./router_config_files/router_3.conf:/root/demo.conf gobgp"
