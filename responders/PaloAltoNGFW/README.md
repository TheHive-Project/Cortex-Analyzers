### Описание работы responder модуля для системы Palo Alto NGFW

Данное описание содержит требуемые действия от инженера для интеграции работы responder с Palo Alto NGFW.

#### Installation

need install:
1. pip install cortexutils
2. pip install requests
3. pip install pan-os-python
4. pip install thehive4py

###  ToDo
Для работы responders, необходимо загрузить папку PaloAltoNGFW в директорию, где храняться другие responder.
Далее необходимо:
- Выполнить перезагрузку системы cortex;

- Для настройки респондера необходимо перейти в веб консоли cortex перейти на вкладку "Organization", выбрать организацию для которой будет выполнена настройка и перейти на вкладку "Responders Config" и выполняем настройку полей для "PaloAltoNGFW_main" в соответсвии с их значениями:
![alt text](assets/Responders.jpg)
1. Hostname_PaloAltoNGFW - сетевой адрес системы PaloAltoNGFW
2. User_PaloAltoNGFW - пользователь в системе PaloAltoNGFW
3. Password_PaloAltoNGFW - пароль для пользователя в системе PaloAltoNGFW
4. Security_rule_* - имя правила безопасности в системе PaloAltoNGFW. Установлены следующие стандартные наименования правил:  
4.1 Для блокировки\разблокировки имени пользователей:  
4.1.1 "TheHive Block internal user"  
4.1.2 "TheHive Block external user"  

4.2 Для блокировки\разблокировки сетевых адресов:  
4.2.1 "TheHive Block internal IP address"  
4.2.2 "TheHive Block external IP address"  

4.3 Для блокировки\разблокировки FQDN:  
4.3.1 "TheHive Block external Domain"  
4.3.2 "TheHive Block internal Domain"  

4.4 Для блокировки\разблокировки портов:  
4.4.1 "TheHive Block port for internal communication"  
4.4.2 "TheHive Block port for external communication"  

4.5 TheHive_instance - url адрес системы TheHive (используется только для типов case и alert).
Важно для каждой организации должен быть свой пользователь с API!

4.6 TheHive_API_key - API ключ для подключения к системе TheHive  
Примечание: указанные правила безопасноти должны быть созданы в PaloAltoNGFW, а так же расставлены в порядке их применения.  
Типы используемых данных для работы в системе TheHive:
1. Сетевой адрес - 'ip'
2. FQDN - 'hostname'
3. порт-протокол - 'port-protocol'
4. имя пользователя - 'username'  
Примечание: типы 'port-protocol' и 'username' необходимо создать в системе TheHive. По умолчанию TheHive не имеет данных типов данных в Observable type, поэтому мы должны добавить его в настройках администратора.  
![alt text](assets/AddObservableType.jpg)