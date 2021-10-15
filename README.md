Установка OpenVPN на Ubuntu 20.04
``` 
cd ~
https://raw.githubusercontent.com/fogiznt/OVPN-Ubuntu-20.04-RSA/main/openvpn-install.sh -O openvpn-install.sh
chmod +x openvpn-install.sh
./openvpn-install.sh
```

Добавление пользователей  
Пользователи лежат на вебстраничке вашего сервера, если веб страничка не работает, то в директории /var/www/html/clients/
```
cd ~ 
./account_manager.sh
```
