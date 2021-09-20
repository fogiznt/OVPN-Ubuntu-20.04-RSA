#!/bin/sh
apt update --fix-missing
apt install openvpn easy-rsa curl -y
cd /usr/share/easy-rsa
./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa build-server-full server nopass
#./easyrsa build-client-full client1 nopass
./easyrsa gen-dh
openvpn --genkey --secret /etc/openvpn/tls.key
cd pki
cp ca.crt /etc/openvpn/
cp ./private/server.key /etc/openvpn
#cp ./private/client1.key /etc/openvpn
cp ./issued/server.crt /etc/openvpn
#cp ./issued/client1.crt /etc/openvpn
cp dh.pem /etc/openvpn

cd /etc/openvpn
cat >>server.conf <<EOF
dev tun
proto udp
server 10.8.8.0 255.255.255.0
port 443

ca ca.crt
cert server.crt
key server.key
dh dh.pem

auth SHA512
tls-crypt tls.key 
tls-server

topology subnet
client-to-client
client-config-dir ccd

push "redirect-gateway def1"
push "dhcp-option DNS 1.1.1.1"

sndbuf 524288
rcvbuf 524288
push "sndbuf 524288"
push "rcvbuf 524288"
comp-lzo
tun-mtu 1420

cipher AES-256-CBC
keepalive 10 20
persist-key
persist-tun

log log.log
status status.log
EOF
mkdir /etc/openvpn/ccd
mkdir /etc/openvpn/clients
touch /etc/openvpn/passwords

systemctl start openvpn@server
#ip=$(hostname -I)
ip=$(curl check-host.net/ip)
iptables -t nat -A POSTROUTING --src 10.8.8.0/24 -j SNAT --to-source $ip
echo 1 > /proc/sys/net/ipv4/ip_forward
echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf
apt install iptables-persistent -y
netfilter-persistent save
apt install apache2 zip -y

cd /var/www/html/
mkdir clients
rm index.html
cat >>index.html <<EOF
<!doctype html>
<html >
<head>
  <meta charset="utf-8" />
  <title></title>
</head>
<body>
 <a href="/clients">Клиенты</a>
</body>
</html>
EOF
cd ~
wget https://raw.githubusercontent.com/fogiznt/openvpn_ubuntu20.04_tls/main/account_manager.sh?token=AUNZ56K6OD5QGNETVXLU5U3BJAH4G
chmod +x account_manager.sh

