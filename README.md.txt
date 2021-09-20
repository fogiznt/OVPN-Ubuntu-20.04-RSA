Установка OpenVPN на Ubuntu 20.04
``` 
cd ~
wget https://raw.githubusercontent.com/fogiznt/Ubuntu_20.04_openVPN/main/openvpn_tls_ubuntu20.04_install.sh
chmod +x openvpn_tls_ubuntu20.04_install.sh
./openvpn_tls_ubuntu20.04_install.sh
```

Добавление пользователей  
Пользователи лежат на вебстраничке вашего сервера, если веб страничка не работает, то в директории /var/www/html/clients/
```
cd ~ 
./account_manager.sh
```
