# Описание работы responder модуля для системы Palo Alto NGFW

Данное описание содержит требуемые действия от инженера для интеграции работы responder с Palo Alto NGFW.

# Installation

need install:
1. cortexutils
2. requests
3. pan-os-python
4. thehive4py
# ToDo

Для работы responders, необходимо загрузить папку PaloAltoNGFW в директорию, где храняться другие responder. Далее перейти в загруженную папку и сделать запускаемыми скрипты на языке python командой "chmod +x *.py"

Далее необходимо:
Выполнить перезагрузку системы cortex;

После перезагрузки в веб консоли cortex перейти на вкладку "Organization", выбрать организацию для которой будет выполнена настройка и перейти на вкладку "Responders", выбрать интерисующий Вас responder и настроить поля в соответсвии с их значениями:
![alt text](Responders.jpg)
1. Hostname_PaloAltoNGFW - сетевой адрес системы PaloAltoNGFW
2. User_PaloAltoNGFW - пользователь в системе PaloAltoNGFW
3. Password_PaloAltoNGFW - пароль для пользователя в системе PaloAltoNGFW
4. name_security_rule (не обязательное поле) - имя правила безопасности в системе PaloAltoNGFW. Установлены следующие стандартные наименования правил:  
4.1 Для блокировки\разблокировки имени пользователей:  
4.1.1 "TheHive Block user internal communication"  
4.1.2 "TheHive Block user external communication"  

4.2 Для блокировки\разблокировки сетевых адресов:  
4.2.1 "TheHive Block internal IP address"  
4.2.2 "TheHive Block external IP address"  

4.3 Для блокировки\разблокировки FQDN:  
4.3.1 "TheHive Block external Domain"  
4.3.2 "TheHive Block internal Domain"  

4.4 Для блокировки\разблокировки портов:  
4.4.1 "TheHive Block internal port"  
4.4.2 "TheHive Block external port"  

4.5 thehive_instance - url адрес системы TheHive (используется только для типов case и alert)

4.6 thehive_api_key - API ключ для подключения к системе TheHive  
Примечание: указанные правила безопасноти должны быть созданы в PaloAltoNGFW, а так же расставлены в порядке их применения.  
Типы используемых данных для работы в системе TheHive:
1. Сетевой адрес - 'ip'
2. FQDN - 'hostname'
3. порт - 'port'
4. имя пользователя - 'user-agent'  
Примечание: данный тип необходимо создать в системе TheHive. По умолчанию TheHive не имеет типа данных "user-agent" в Observable type, поэтому мы должны добавить его в настройках администратора.  
![alt text](AddObservableType.jpg)