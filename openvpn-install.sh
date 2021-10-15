#!/bin/bash
RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
DEFAULT='\033[0m'

echo -e "${GREEN}  ____                     _   __   ___    _  __                      ";
echo -e " / __ \   ___  ___   ___  | | / /  / _ \  / |/ /                      ";
echo -e "/ /_/ /  / _ \/ -_) / _ \ | |/ /  / ___/ /    /                       ";
echo -e "\____/  / .__/\__/ /_//_/ |___/  /_/    /_/|_/                        ";
echo -e "       /_/                                                            ";
echo -e "  __  __   __               __               ___   ___      ___   ____";
echo -e " / / / /  / /  __ __  ___  / /_ __ __       |_  | / _ \    / _ \ / / /";
echo -e "/ /_/ /  / _ \/ // / / _ \/ __// // /      / __/ / // / _ / // //_  _/";
echo -e "\____/  /_.__/\_,_/ /_//_/\__/ \_,_/      /____/ \___/ (_)\___/  /_/  ";
echo -e "                                                                      ${DEFAULT}";

echo -n -e "${GREEN}Обновление пакетов ${DEFAULT}" & echo $(apt update 2>/dev/null | grep packages | cut -d '.' -f 1)
echo -e "Установка пакетов: "

echo -n -e "               openvpn " & echo -n $(apt install openvpn -y >&- 2>&-)
if [ "$(dpkg --get-selections openvpn | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install openvpn ${DEFAULT}" ;fi

echo -n -e "               easy-rsa " & echo -n $(apt install easy-rsa -y >&- 2>&-)
if [ "$(dpkg --get-selections easy-rsa | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install easy-rsa ${DEFAULT}" ;fi

echo -n -e "               curl " & echo -n $(apt install curl -y >&- 2>&-)
if [ "$(dpkg --get-selections curl | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install curl ${DEFAULT}" ;fi

echo -n -e "               iptables-persistent "
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
apt install iptables-persistent -y >&- 2>&-
if [ "$(dpkg --get-selections iptables-persistent | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install iptables-persistent ${DEFAULT}" ;fi

echo -n -e "               apache2 " & echo -n $(apt install apache2 -y >&- 2>&-)
if [ "$(dpkg --get-selections apache2 | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install apache2 ${DEFAULT}" ;fi

echo -n -e "               zip " & echo -n $(apt install zip -y >&- 2>&-)
if [ "$(dpkg --get-selections zip | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install zip ${DEFAULT}" ;fi

cd /usr/share/easy-rsa/

echo -e "Генерация сертификатов: "

./easyrsa init-pki >&- 2>&-
echo -n "               CA "
export EASYRSA_BATCH=1
./easyrsa build-ca nopass >&- 2>&-
cp pki/ca.crt /etc/openvpn/
if ! [ -f /etc/openvpn/ca.crt ];then echo -e "${RED}ОШИБКА, сертификат CA не сгенерирован, выход из программы${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}";fi

echo -n -e "               Сертификат сервера "
./easyrsa build-server-full server nopass >&- 2>&-
cp pki/private/server.key /etc/openvpn
cp pki/issued/server.crt /etc/openvpn
if ! [ -f /etc/openvpn/server.key ];then echo -e "${RED}ОШИБКА, сертификат сервера не сгенерирован, выход из программы${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}"; fi
echo -n -e "               Ключ сервера "
if ! [ -f /etc/openvpn/server.crt ];then echo -e "${RED}ОШИБКА, ключ сервера не сгенерирован, выход из программы${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}";fi

echo -n -e "               Ключи Диффи-Хеллмана "
./easyrsa gen-dh >&- 2>&-
cp pki/dh.pem /etc/openvpn
if ! [ -f /etc/openvpn/dh.pem ];then echo -e "${RED}ОШИБКА, ключи Диффи-Хеллмана не сгенерированы, выход из программы${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}";fi
openvpn --genkey --secret /etc/openvpn/tls.key

echo -n -e "${DEFAULT}Настройка и запуск OpenVPN сервера "

cd /etc/openvpn
cat >>server.conf <<EOF
dev tun
proto udp4
server 10.8.8.0 255.255.255.0
port 443
ca ca.crt
cert server.crt
key server.key
dh dh.pem
cipher AES-256-GCM
auth SHA512

tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
tls-crypt tls.key
tls-server

topology subnet
client-to-client
client-config-dir ccd
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

tun-mtu 1500
keysize 256
key-method 2

#sndbuf 524288
#rcvbuf 524288
#push "sndbuf 524288"
#push "rcvbuf 524288"
#comp-lzo
#push "comp-lzo yes"
keepalive 10 30
persist-key
persist-tun
log log.log
status status.log
EOF

mkdir /etc/openvpn/ccd
mkdir /etc/openvpn/clients
touch /etc/openvpn/passwords

systemctl start openvpn@server
if ! [ "$(systemctl status openvpn@server | grep -o "running" )" = "running" ]; then
echo -e "${RED}ОШИБКА, Openvpn сервер не запустился, выход из программы. \n Вы можете посмотреть логи сервер - cat /etc/openvpn/log.log или systemctl status openvpn@server${DEFAULT}"
else
echo -e "${GREEN}сервер запущен${DEFAULT}"
fi

ip=$(curl check-host.net/ip) >&- 2>&-
#ip=$(hostname -i)
echo -e "${GREEN}SNAT 10.8.8.0/24 -------> $ip ${DEFAULT}"
iptables -t nat -A POSTROUTING -s 10.8.8.0/24 -j SNAT --to-source $ip
echo 1 > /proc/sys/net/ipv4/ip_forward
echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf
netfilter-persistent save >&- 2>&-

echo -n -e "Настройка web-сервера apache2 "
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
touch account_manager.sh
cat >account_manager.sh <<FOE
#!/bin/sh
RED='\033[37;0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
DEFAULT='\033[0m'

f=1
while f=1
do
echo "\n\${RED}Настройка пользователей VPN\nВыберите действие\${DEFAULT}
\${GREEN}---------------------------------------\${DEFAULT}
1 - Список учётных записей VPN        \033[0;32m|\${DEFAULT}
2 - Список подключённых пользователей \033[0;32m|\${DEFAULT}
3 - Пароли от архивов                 \033[0;32m|\${DEFAULT}
4 - Добавить учётную запись           \033[0;32m|\${DEFAULT}
5 - Удалить учётную запись            \033[0;32m|\${DEFAULT}
6 - Выйти из программы\${DEFAULT}                \033[0;32m|\${DEFAULT}
\${GREEN}---------------------------------------|\${DEFAULT}"
read value
case "\$value" in
1) echo "\${RED}Список учётных записей для подключения:\${DEFAULT}"
val1=\$(ls /etc/openvpn/ccd/)
if [ "\$val1" = "" ];
then
echo "\${GREEN}Учётных записей для подключения нет.Добавте новые\${DEFAULT}"
else
grep -H -o "10.8.8.*" /etc/openvpn/ccd/* | cut -b 18-60
fi;;
2)
val=\$(cat /etc/openvpn/status.log | grep 10.8.8)
echo "\${GREEN}Список подключёных пользователей:\${DEFAULT}"
if [ "\$val" = "" ];
then
echo "\${GREEN}Нет подключённых пользователей\${DEFAULT}"
else
echo "\${GREEN}Локальный ip,учётка,ip адрес пользователя\${DEFAULT}"
cat /etc/openvpn/status.log | grep 10.8.8
fi;;

4) echo "\${GREEN}Добавление учётной запсиси\${DEFAULT}\nВведите имя учётной записи"
read username
echo "\${RED}Введите пароль\${DEFAULT}"
read password
echo "\${RED}Введите локальный ip, к которому будет привязана учётная запись\${DEFAULT}"
val1=\$(ls /etc/openvpn/ccd/)
if [ "\$val1" = "" ];
then
echo "\${GREEN}Рекомендую использовать диапозон адресов 10.8.8.100 - 10.8.8.200\${DEFAULT}"
else
echo "\${GREEN}Для сравнения - список назначенных учётным записям локальных ip адресов\${DEFAULT}"
grep -H -o "10.8.8.*" /etc/openvpn/ccd/* | cut -b 18-60
fi
read local_ip
cd /etc/openvpn/
touch passwords
cat >>passwords <<EOF
\$username \$password
EOF

cd /usr/share/easy-rsa
./easyrsa build-client-full \$username nopass
cd /etc/openvpn/clients/
ca=\$(cat /usr/share/easy-rsa/pki/ca.crt)
cert=\$(cat /usr/share/easy-rsa/pki/issued/\$username.crt)
key=\$(cat /usr/share/easy-rsa/pki/private/\$username.key)
tls=\$(cat /etc/openvpn/tls.key)
dh=\$(cat /etc/openvpn/dh.pem)
#ip=$(hostname -I)
ip=\$(curl check-host.net/ip)
cat >\$username.ovpn <<EOF
client
dev tun
proto udp
remote \$ip 443

cipher AES-256-GCM
auth SHA512

persist-key
persist-tun

#comp-lzo adaptive
resolv-retry infinite
remote-cert-tls server
ignore-unknown-option block-outside-dns
block-outside-dns
nobind
verb3
<ca>
\$ca
</ca>
<cert>
\$cert
</cert>
<key>
\$key
</key>
<tls-crypt>
\$tls
</tls-crypt>
EOF
cd /etc/openvpn/ccd/
cat >\$username <<EOF
ifconfig-push \$local_ip 255.255.255.0
EOF
cd /etc/openvpn/clients/
zip \$username.zip -P \$password  \$username.ovpn
cd /var/www/html/clients/
mv /etc/openvpn/clients/\$username.zip .
echo "\${GREEN} Учётная запись добавлена\${DEFAULT}";;

5) echo "\${GREEN}Удаление учётной записи\${DEFAULT}\nВведите имя учётной записи"
read username
if  [ -e /etc/openvpn/ccd/\$username ];
then
rm -f /etc/openvpn/clients/\$username.ovpn
rm /usr/share/easy-rsa/pki/issued/\$username.crt
rm /usr/share/easy-rsa/pki/private/\$username.key
rm /var/www/html/clients/\$username.zip
rm /etc/openvpn/ccd/\$username
sed -i /\$username/d /etc/openvpn/passwords
echo "\${GREEN} Учётная запись удалёна\${DEFAULT}"
rm /usr/share/easy-rsa/pki/reqs/\$username.req
else
echo "\${RED}Неправильно введено имя учётной записи\${DEFAULT}"
fi;;
3)echo "\${GREEN}Логин/пароль от архива\${DEFAULT}"
cat /etc/openvpn/passwords;;
6)echo "\${GREEN} Выход из программы\${DEFAULT}"
exit;;
esac
done
FOE
chmod +x account_manager.sh

if ! [ "$(systemctl status apache2 | grep -o "running" )" = "running" ]; then
echo -e "${RED}- не критичная ошибка,web-сервер не запустился, все ваши файлы для подключения будут лежать в /var/www/html/clients${DEFAULT}"
else
echo -e "${GREEN}завершена.${DEFAULT}"
fi

echo -e "${GREEN}   ____             __          __   __                                __       __           __";
echo -e "  /  _/  ___   ___ / /_ ___ _  / /  / /      ____ ___   __ _    ___   / / ___  / /_ ___  ___/ /";
echo -e " _/ /   / _ \ (_-</ __// _ \`/ / /  / /      / __// _ \ /  ' \  / _ \ / / / -_)/ __// -_)/ _  / ";
echo -e "/___/  /_//_//___/\__/ \_,_/ /_/  /_/       \__/ \___//_/_/_/ / .__//_/  \__/ \__/ \__/ \_,_/  ";
echo -e "                                                             /_/                               ";
echo -e "                                                                                               ${DEFAULT}";

echo -e "${GREEN}Основные параметры сервера
public ip - $ip	  cipher - AES-256-GCM
proto - udp4                    tls-crypt - enable
port - 443                      tls version - 1.2
ip in VPN network - 10.8.8.1    tls-cipher - TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
DNS for clients - 8.8.8.8       auth - SHA512
mode - tun                      key-size - 256
tun-mtu - 1500                  key-method - 2${DEFAULT}"
