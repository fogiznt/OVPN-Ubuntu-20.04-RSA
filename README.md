Установка OpenVPN на Ubuntu 20.04
``` 
cd ~
wget https://raw.githubusercontent.com/fogiznt/openvpn_ubuntu20.04_tls/main/openvpn_tls_ubuntu20.04_install.sh?token=AUNZ56NMO2V4VERU6YJWCJ3BJAHY6
chmod +x openvpn_tls_ubuntu20.04_install.sh
./openvpn_tls_ubuntu20.04_install.sh
```

Добавление пользователей  
Пользователи лежат на вебстраничке вашего сервера, если веб страничка не работает, то в директории /var/www/html/clients/
```
cd ~ 
./account_manager.sh
```
