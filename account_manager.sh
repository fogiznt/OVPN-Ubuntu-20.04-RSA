#!/bin/sh
RED='\033[37;0;31m'
GREEN='\033[0;32;4m'
BLUE='\033[0;34m'
DEFAULT='\033[0m'

f=1
while f=1
do
echo "\n${RED}Настройка пользователей VPN\nВыберите действие${DEFAULT}
${GREEN}                                      ${DEFAULT}
${BLUE}1 - Список учётных записей VPN        \033[0;32m|${DEFAULT}
${BLUE}2 - Список подключённых пользователей \033[0;32m|${DEFAULT}
${BLUE}3 - Пароли от архивов                 \033[0;32m|${DEFAULT}
${BLUE}4 - Добавить учётную запись           \033[0;32m|${DEFAULT}
${BLUE}5 - Удалить учётную запись            \033[0;32m|${DEFAULT}
${BLUE}6 - Выйти из программы${DEFAULT}                \033[0;32m|${DEFAULT}
${GREEN}                                      |${DEFAULT}"
read value
case "$value" in
1) echo "${RED}Список учётных записей для подключения:${DEFAULT}"
val1=$(ls /etc/openvpn/ccd/)
if [ "$val1" = "" ];
then
echo "${GREEN}Учётных записей для подключения нет.Добавте новые${DEFAULT}"
else
grep -H -o "10.8.8.*" /etc/openvpn/ccd/* | cut -b 18-60
fi;;
2)
val=$(cat /etc/openvpn/status.log | grep 10.8.8)
echo "${RED}Список подключёных пользователей:${DEFAULT}"
if [ "$val" = "" ];
then
echo "${GREEN}Нет подключённых пользователей${DEFAULT}"
else
echo "${GREEN}Локальный ip,учётка,ip адрес пользователя${DEFAULT}"
cat /etc/openvpn/status.log | grep 10.8.8
fi;;

4) echo "${RED}Добавление учётной запсиси${DEFAULT}\nВведите имя учётной записи"
read username
echo "${RED}Введите пароль${DEFAULT}"
read password
echo "${RED}Введите локальный ip, к которому будет привязана учётная запись${DEFAULT}"
val1=$(ls /etc/openvpn/ccd/)
if [ "$val1" = "" ];
then
echo "${GREEN}Рекомендую использовать диапозон адресов 10.8.8.100 - 10.8.8.200${DEFAULT}"
else
echo "${GREEN}Для сравнения - список назначенных учётным записям локальных ip адресов${DEFAULT}"
grep -H -o "10.8.8.*" /etc/openvpn/ccd/* | cut -b 18-60
fi
read local_ip
cd /etc/openvpn/
touch passwords
cat >>passwords <<EOF
$username $password
EOF
cd /usr/share/easy-rsa
./easyrsa build-client-full $username nopass
mkdir /etc/openvpn/clients/$username
cd /etc/openvpn/clients/$username
ca=$(cat /usr/share/easy-rsa/pki/ca.crt)
cert=$(cat /usr/share/easy-rsa/pki/issued/$username.crt)
key=$(cat /usr/share/easy-rsa/pki/private/$username.key)
tls=$(cat /etc/openvpn/tls.key)
dh=$(cat /etc/openvpn/dh.pem)
#ip=$(hostname -I)
ip=$(curl check-host.net/ip)
cat >$username.ovpn <<EOF
client
dev tun
proto udp
remote $ip 443

persist-key
persist-tun

comp-lzo yes
remote-cert-tls server
cipher AES-128-GCM
auth MD5

ignore-unknown-option block-outside-dns
block-outside-dns
nobind
verb3

<ca>
$ca
</ca>
<cert>
$cert
</cert>
<key>
$key
</key>
<tls-crypt>
$tls
</tls-crypt>
EOF
cd /etc/openvpn/ccd/
cat >$username <<EOF
ifconfig-push $local_ip 255.255.255.0
EOF
cd /etc/openvpn/clients/$username/
zip $username.zip -P $password  $username.ovpn
cp /etc/openvpn/clients/$username/$username.zip /home/clients/
cd /var/www/html/clients/
cp /etc/openvpn/clients/$username/$username.zip .
echo "${GREEN} Учётная запись добавлена${DEFAULT}";;

5) echo "${RED}Удаление учётной записи${DEFAULT}\nВведите имя учётной записи"
read username
if  [ -e /etc/openvpn/ccd/$username ];
then
rm -r /etc/openvpn/clients/$username
rm /usr/share/easy-rsa/pki/issued/$username.crt
rm /usr/share/easy-rsa/pki/private/$username.key
rm /var/www/html/clients/$username.zip
rm /etc/openvpn/ccd/$username
sed -i /$username/d /etc/openvpn/passwords
echo "${GREEN} Учётная запись удалёна${DEFAULT}"
rm /usr/share/easy-rsa/pki/reqs/$username.req
else
echo "${RED}Неправильно введено имя учётной записи${DEFAULT}"
fi;;
3)echo "${RED}Логин/пароль от архива${DEFAULT}"
cat /etc/openvpn/passwords;;
6)echo "${GREEN} Выход из программы${DEFAULT}"
exit;;
esac
done


