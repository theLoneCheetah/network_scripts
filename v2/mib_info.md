- [Известные MIBs](#известные-mibs)
  - [Standard MIBs](#standard-mibs)
  - [Private D-Link MIBs](#private-d-link-mibs)
- [Используемые MIBs](#используемые-mibs)
  - [DES-3028](#des-3028)
- [Реализуемые функции](#реализуемые-функции)
  - [DES-3028](#des-3028-1)
- [Справочник](#справочник)
  - [Trusted host](#trusted-host)
    - [Команды](#команды)
  - [Access profile](#access-profile)
    - [Packet Content Frame Filter](#packet-content-frame-filter)
  - [VLAN](#vlan)
    - [Команды на DES-3028 (vlanid=2)](#команды-на-des-3028-vlanid2)
    - [Комбинации запросов](#комбинации-запросов)
  - [DHCP relay](#dhcp-relay)
    - [Механизм работы](#механизм-работы)
    - [Команды на DES-3028](#команды-на-des-3028)
  - [Port security](#port-security)
    - [Команды на DES-3028 (port=21)](#команды-на-des-3028-port21)
# Известные MIBs

## Standard MIBs
- <a name="APPLICATION-MIB"></a>**APPLICATION-MIB** - мониторинг L7 сервисов
- <a name="ATM-MIB"></a>**ATM-MIB** - сети ATM
- <a name="BRIDGE-MIB"></a>**BRIDGE-MIB** - STP, базовая информация по трафику портов и макам, мак и количество портов свитча
- <a name="CHARACTER-MIB"></a>**CHARACTER-MIB** - мониторинг устройств с поддержкой символьного потока
- <a name="CISCO-LWAPP-AP-MIB"></a>**CISCO-LWAPP-AP-MIB** - точки доступа Wi-Fi с протоколом LWAPP
- <a name="CISCO-SMI-V1SMI"></a>**CISCO-SMI-V1SMI** - файл структур Cisco
- <a name="CLNS-MIB"></a>**CLNS-MIB** - мониторинг стека протоколов OSI (CLNP)
- <a name="DECNET-PHIV-MIB"></a>**DECNET-PHIV-MIB** - сети DECnet Phase IV
- <a name="DSA-MIB"></a>**DSA-MIB** - сервера X.500
- <a name="ENTITY-MIB"></a>**ENTITY-MIB** - псевдоним [RFC2737-MIB](#RFC2737-MIB)
- <a name="ETHERLIKE-MIB"></a>**ETHERLIKE-MIB** - псевдоним (в данном случае немного устаревшая версия) [RFC2665-MIB](#RFC2665-MIB)
- <a name="FDDI-SMT73-MIB"></a>**FDDI-SMT73-MIB** - оптоволоконные сети FDDI
- <a name="HOST-RESOURCES-MIB"></a>**HOST-RESOURCES-MIB** - ресурсы ОС серверов
- <a name="IE8023AH-MIB"></a>**IE8023AH-MIB** - диагностика связи между коммутатором и портом, тесты, уведомления, последнее состояние
- <a name="IE8021X-MIB"></a>**IE8021X-MIB** - контроль доступа и авторизация по портам
- <a name="IANAIFTYPE-MIB"></a>**IANAIFTYPE-MIB** - справочник типов интерфейсов
- <a name="IF-MIB"></a>**IF-MIB** - псевдоним [RFC2863-MIB](#RFC2863-MIB)
- <a name="INET-ADDRESS-MIB"></a>**INET-ADDRESS-MIB** - справочник для IPv4, IPv6, DNS
- <a name="IP-MIB"></a>**IP-MIB** - расширение [RFC1213-MIB](#RFC1213-MIB) для IP (включая IPv6) и ICMP
- <a name="LLDP-MIB"></a>**LLDP-MIB** - сбор и обмен базовой информации о соседних устройствах по протоколу LLDP
- <a name="LLDP_EXT_DOT1-MIB"></a>**LLDP_EXT_DOT1-MIB** - информация о VLAN по LLDP
- <a name="LLDP_EXT_DOT3-MIB"></a>**LLDP_EXT_DOT3-MIB** - состояние порта по LLDP
- <a name="NET-SNMP-AGENT-MIB"></a>**NET-SNMP-AGENT-MIB** - состояние SNMP-сервиса для Net-SNMP
- <a name="NET-SNMP-EXAMPLES-MIB"></a>**NET-SNMP-EXAMPLES-MIB** - спецификации для Net-SNMP
- <a name="NET-SNMP-MIB"></a>**NET-SNMP-MIB** - корневая структура Net-SNMP
- <a name="NET-SNMP-TC"></a>**NET-SNMP-TC** - примеры для Net-SNMP
- <a name="OAM-MIB"></a>**OAM-MIB** - псевдоним [IE8023AH-MIB](#IE8023AH-MIB)
- <a name="P-BRIDGE-MIB"></a>**P-BRIDGE-MIB** - псевдоним [RFC2674P-MIB](#RFC2674P-MIB)
- <a name="PARALLEL-MIB"></a>**PARALLEL-MIB** - для устройств с параллельным интерфейсом (LPT-портом)
- <a name="PRINTER-MIB"></a>**PRINTER-MIB** - сетевые принтеры
- <a name="Q-BRIDGE-MIB"></a>**Q-BRIDGE-MIB** - псевдоним (в данном случае немного устаревшая версия) [RFC2674Q-MIB](#RFC2674Q-MIB)
- <a name="RFC1066-MIB"></a>**RFC1066-MIB** - старая версия [RFC1156-MIB](#RFC1156-MIB) (и [RFC1213-MIB](#RFC1213-MIB))
- <a name="RFC1155-SMI"></a>**RFC1155-SMI** - файл базовых структур, алфавитов и типов, используется для импортов и не содержит OID
- <a name="RFC1156-MIB"></a>**RFC1156-MIB** - старая версия [RFC1213-MIB](#RFC1213-MIB)
- <a name="RFC1158-MIB"></a>**RFC1158-MIB** - старая, переходная версия [RFC1213-MIB](#RFC1213-MIB)
- <a name="RFC1212-MIB"></a>**RFC1212-MIB** - файл макросов для [RFC1213-MIB](#RFC1213-MIB)
- <a name="RFC1213-MIB"></a>**RFC1213-MIB** - базовые данные системы (модель, private OID), интерфейсов, ICMP, TCP, UDP, SNMP, информация по IP интерфейсам, таблице маршрутищации, ARP таблице
- <a name="RFC1229-MIB"></a>**RFC1229-MIB** - расширение для интерфейсов, счётчики
- <a name="RFC1231-MIB"></a>**RFC1231-MIB** - старая версия [RFC1743.MI2](#RFC1743.MI2)
- <a name="RFC1232-MIB"></a>**RFC1232-MIB** - старая версия [RFC1406-MIB](#RFC1406-MIB)
- <a name="RFC1233-MIB"></a>**RFC1233-MIB** - старая версия [RFC1407-MIB](#RFC1407-MIB)
- <a name="RFC1253-MIB"></a>**RFC1253-MIB** - управление OSPF версии 2
- <a name="RFC1271-MIB"></a>**RFC1271-MIB** - старая версия [RMON-MIB](#RMON-MIB)
- <a name="RFC1289-MIB"></a>**RFC1289-MIB** - сети DECnet
- <a name="RFC1304-MIB"></a>**RFC1304-MIB** - сети SMDS
- <a name="RFC1315-MIB"></a>**RFC1315-MIB** - сети Frame Relay
- <a name="RFC1316-MIB"></a>**RFC1316-MIB** - старая версия [CHARACTER-MIB](#CHARACTER-MIB)
- <a name="RFC1317-MIB"></a>**RFC1317-MIB** - мониторинг портов RS-232 (COM-портов)
- <a name="RFC1318-MIB"></a>**RFC1318-MIB** - старая версия [PARALLEL-MIB](#PARALLEL-MIB)
- <a name="RFC1381-MIB"></a>**RFC1381-MIB** - протокол LAPB сетей X.25
- <a name="RFC1382-MIB"></a>**RFC1382-MIB** - сети X.25
- <a name="RFC1389-MIB"></a>**RFC1389-MIB** - управление RIPv2
- <a name="RFC1398-MIB"></a>**RFC1398-MIB** - старая версия [RFC1623.MIB](#RFC1623.MIB)
- <a name="RFC1406-MIB"></a>**RFC1406-MIB** - телефония DS1/E1
- <a name="RFC1407-MIB"></a>**RFC1407-MIB** - телефония DS3/E3
- <a name="RFC1414-MIB"></a>**RFC1414-MIB** - информация о TCP-соединениях
- <a name="RFC1493.MIB"></a>**RFC1493.MIB** - старая версия [BRIDGE-MIB](#BRIDGE-MIB)
- <a name="RFC1623.MIB"></a>**RFC1623.MIB** - старая версия [RFC1643.MIB](#RFC1643.MIB)
- <a name="RFC1643.MIB"></a>**RFC1643.MIB** - старая версия [ETHERLIKE-MIB](#ETHERLIKE-MIB) и [IF-MIB](#IF-MIB)
- <a name="RFC1665.MI2"></a>**RFC1665.MI2** - архитектура SNA от IBM
- <a name="RFC1743.MI2"></a>**RFC1743.MI2** - сети Token Ring
- <a name="RFC1907-MIB"></a>**RFC1907-MIB** - базовые правила работы по SNMP, стандартные поддерживаемые модули
- <a name="RFC2021-MIB"></a>**RFC2021-MIB** - расширение [RMON-MIB](#RMON-MIB) на L3-L7
- <a name="RFC2571-MIB"></a>**RFC2571-MIB** - общая архитектура, движок SNMPv3
- <a name="RFC2572-MIB"></a>**RFC2572-MIB** - упаковка/распаковка сообщений SNMPv3
- <a name="RFC2573N-MIB"></a>**RFC2573N-MIB** - уведомления SNMPv3
- <a name="RFC2573T-MIB"></a>**RFC2573T-MIB** - цели (менеджеры) мониторинга SNMPv3
- <a name="RFC2574-MIB"></a>**RFC2574-MIB** - пользователи SNMPv3
- <a name="RFC2575-MIB"></a>**RFC2575-MIB** - управление доступом SNMPv3
- <a name="RFC2576-MIB"></a>**RFC2576-MIB** - совместимость SNMPv3 со старыми версиями протокола
- <a name="RFC2620-MIB"></a>**RFC2620-MIB** - мониторинг авторизации с использованием RADIUS-сервера
- <a name="RFC2665-MIB"></a>**RFC2665-MIB** - спецификация дуплекса, физических ошибок (CRC: ошибки выравнивания и контрольной суммы) и коллизий для Ethernet-интерфейсов, частично расширение [IF-MIB](#IF-MIB)
- <a name="RFC2674P-MIB"></a>**RFC2674P-MIB** - приоритеты трафика, классы, очереди
- <a name="RFC2674Q-MIB"></a>**RFC2674Q-MIB** - FDB, VLAN (включая static и GVRP)
- <a name="RFC2737-MIB"></a>**RFC2737-MIB** - физическая структура устройства, модули, порты, модель и прошивка
- <a name="RFC2819-MIB"></a>**RFC2819-MIB** - удалённый мониторинг RMON на L2
- <a name="RFC2863-MIB"></a>**RFC2863-MIB** - базовая статистика сетевых интерфейсов, статус, скорость, байты, ошибки (общий счётчик различных физических ошибок), unicast/multicast/broadcast пакеты, соответствие if_index имени ipif
- <a name="RFC2925P-MIB"></a>**RFC2925P-MIB** - запуск пинга
- <a name="RFC2925T-MIB"></a>**RFC2925T-MIB** - запуск трассировки
- <a name="RMON-MIB"></a>**RMON-MIB** - псевдоним [RFC2819-MIB](#RFC2819-MIB)
- <a name="RMON2-MIB"></a>**RMON2-MIB** - псевдоним [RFC2021-MIB](#RFC2021-MIB)
- <a name="SIP-MIB"></a>**SIP-MIB** - мониторинг SMDS Interface Protocol
- <a name="SNA-NAU-MIB"></a>**SNA-NAU-MIB** - псевдоним [RFC1665.MI2](#RFC1665.MI2)
- <a name="SNMP-FRAMEWORK-MIB"></a>**SNMP-FRAMEWORK-MIB** - идентификация устройства по SNMP, управление размером пакетов
- <a name="SNMP-TARGET-MIB"></a>**SNMP-TARGET-MIB** - псевдоним [RFC2573T-MIB](#RFC2573T-MIB)
- <a name="SNMPv2-CONF"></a>**SNMPv2-CONF** - файл описания групп объектов, определения соответствия стандартам
- <a name="SNMPv2-MIB"></a>**SNMPv2-MIB** - базовые переменные SNMP-агента, запросы, ошибки протокола
- <a name="SNMPv2-SMI"></a>**SNMPv2-SMI** - файл базовых структур и типов SNMPv2
- <a name="SNMPv2-TC"></a>**SNMPv2-TC** - файл с определением сокращений
- <a name="SNMPv2-TM"></a>**SNMPv2-TM** - файл с определением упаковки SNMP
- <a name="SNMP-VIEW-BASED-ACM-MIB"></a>**SNMP-VIEW-BASED-ACM-MIB** - управление доступом по SNMP (Views)
- <a name="TCPIPX-MIB"></a>**TCPIPX-MIB** - совмещение мониторинга устройств стеков TCP/IP и IPX/SPX
- <a name="TOKENRING-MIB"></a>**TOKENRING-MIB** - псевдоним [RFC1743.MI2](#RFC1743.MI2)
- <a name="TOKEN-RING-RMON-MIB"></a>**TOKEN-RING-RMON-MIB** - RMON для - старая версия [BRIDGE-MIB](#BRIDGE-MIB), мак свитча, количество портов сетей Token Ring, расширение [TOKENRING-MIB](#TOKENRING-MIB)
- <a name="UCD-DEMO-MIB"></a>**UCD-DEMO-MIB** - демо-файл, старая версия [NET-SNMP-MIB](#NET-SNMP-MIB)
- <a name="UCD-DISKIO-MIB"></a>**UCD-DISKIO-MIB** - активность дисков, старая версия [NET-SNMP-MIB](#NET-SNMP-MIB)
- <a name="UCD-DLMOD-MIB"></a>**UCD-DLMOD-MIB** - динамически загружаемые модули, старая версия [NET-SNMP-MIB](#NET-SNMP-MIB)
- <a name="UCD-IPFWACC-MIB"></a>**UCD-IPFWACC-MIB** - системные брандмауэры, старая версия [NET-SNMP-MIB](#NET-SNMP-MIB)
- <a name="UCD-SNMP-MIB"></a>**UCD-SNMP-MIB** - старая версия [NET-SNMP-MIB](#NET-SNMP-MIB)
- <a name="USM-MIB"></a>**USM-MIB** - псевдоним [RFC2574-MIB](#RFC2574-MIB)

## Private D-Link MIBs
- <a name="AAC-MIB"></a>**AAC-MIB** - доступ, авторизация, права
- <a name="ACL-MIB"></a>**ACL-MIB** - 
- <a name="AUTH-MIB"></a>**AUTH-MIB** - параметры RADIUS-сервера, аутентификация
- <a name="BPDU-PROTECTION-MIB"></a>**BPDU-PROTECTION-MIB** - защита от лишних пакетов протокола STP
- <a name="CABLEDIAG-MIB"></a>**CABLEDIAG-MIB** - кабель диагностика (запуск, состояние и результат)
- <a name="DDM-MIB"></a>**DDM-MIB** - состояние SFP-модулей
- <a name="DHCPRELAY-MIB"></a>**DHCPRELAY-MIB** - dhcp relay без распределения серверов по вланам
- <a name="DOSPREV-MIB"></a>**DOSPREV-MIB** - настройка защиты от DoS
- <a name="DOT1XMGMT-MIB"></a>**DOT1XMGMT-MIB** - Guest VLAN для аутентификации по порту IEEE 802.1X
- <a name="DULD-MIB"></a>**DULD-MIB** - обнаружение однонаправленных каналов
- <a name="FILTER-MIB"></a>**FILTER-MIB** - фильтрация трафика: DHCP-ответы, защита CPU, исходящий трафик
- <a name="GENMGMT-MIB"></a>**GENMGMT-MIB** - частные поддерживаемые модули, утилизация, образы прошивок и системных файлов, save, warm start, trusted hosts, очистка FDB и ARP, gratuitous ARP, настройка COM порта
- <a name="IPMACBIND-MIB"></a>**IPMACBIND-MIB** - привязка IP-MAC-порт
- <a name="L2MGMT-MIB"></a>**L2MGMT-MIB** - базовые управление свитчом, clear all counters, базовое управление портом, qos, bandwidth control, trunk ports, port mirroring, IGMP, traffic segmentation, port security, cos приоритеты, loopback detection, multicast filtering, vlan advertisement, flood fdb
- <a name="LAG-MIB"></a>**LAG-MIB** - агрегированные каналы
- <a name="MLDSNP-MIB"></a>**MLDSNP-MIB** - IGMP snooping для IPv6
- <a name="MSTP-MIB"></a>**MSTP-MIB** - сетевые петли по MSTP с группировкой VLAN
- <a name="PKTSTORMCTRL-MIB"></a>**PKTSTORMCTRL-MIB** - контроль трафика, защита от шторма
- <a name="POE-MIB"></a>**POE-MIB** - управление PoE
- <a name="PPPOEMGMT-MIB"></a>**PPPOEMGMT-MIB** - добавление информации о свитче и порте для PPPoE
- <a name="QINQ-MIB"></a>**QINQ-MIB** - упаковка VLAN внутри VLAN
- <a name="SAFEGUARD-MIB"></a>**SAFEGUARD-MIB** - управление SafeGuard, защитой от перегрузки процессора
- <a name="SINGLEIP-MIB"></a>**SINGLEIP-MIB** - управление группов коммутаторов через один IP
- <a name="SMTP-MIB"></a>**SMTP-MIB** - почтовые службы, отправка Trap почтовому серверу
- <a name="SSH-MIB"></a>**SSH-MIB** - управление SSH
- <a name="SSLMIB-MIB"></a>**SSLMIB-MIB** - управление SSL/TLS для доступа к веб-интерфейсу
- <a name="SYSLOG-MIB"></a>**SYSLOG-MIB** - управление системным журналом, пересылкой логов (без сохранения на свитче)
- <a name="TIME-MIB"></a>**TIME-MIB** - системное время, синхронизация по SNTP
- <a name="TIMERANGE-MIB"></a>**TIMERANGE-MIB** - настройка временных диапазонов для активации правил ACL (в том числ для CPU)

# Используемые MIBs
## DES-3028
- ? [ACL-MIB](#ACL-MIB)
- [BRIDGE-MIB](#BRIDGE-MIB) - мак и количество портов свитча
- [CABLEDIAG-MIB](#CABLEDIAG-MIB) - кабель диагностика (запуск, состояние и результат)
- [DHCPRELAY-MIB](#DHCPRELAY-MIB) - dhcp relay без распределения серверов по вланам
- [GENMGMT-MIB](#GENMGMT-MIB) - частные поддерживаемые модули, утилизация, save, trusted hosts, очистка FDB
- [L2MGMT-MIB](#L2MGMT-MIB) - базовые управление свитчом и портом, clear all counters, bandwidth control, traffic segmentation, port security, loopback detection, flood fdb
- [PKTSTORMCTRL-MIB](#PKTSTORMCTRL-MIB) - контроль трафика
- [RFC1213-MIB](#RFC1213-MIB) - базовые данные системы (модель, private OID), ARP-таблица
- [RFC1907-MIB](#RFC1907-MIB) - стандартные поддерживаемые модули
- [RFC2665-MIB](#RFC2665-MIB) - ошибки CRC (ошибки выравнивания и контрольной суммы)
- [RFC2674Q-MIB](#RFC2674Q-MIB) - FDB, VLAN (создание, tag, при этом PVID выставляется автоматически)
- [RFC2863-MIB](#RFC2863-MIB) - соответствие if_index имени ipif, unicast/multicast/broadcast пакеты
- [TIME-MIB](#TIME-MIB) - системное время

# Реализуемые функции
## DES-3028
- private mib modules
  - description
  - version
  - value type
- switch:
  - ip, mask, default gateway, management vlan id, management
  - mac address, ports number
  - current time, management
  - cpu and dram utilization
  - reboot, reset
  - save
  - clear all counters
- trusted host:
  - ip, mask
  - add, delete host
  - delete all hosts
- ? acl
- vlan:
  - names, entry status
  - create, delete
  - egress and untagged ports, add and remove
  - pvid adds/removes automatically with untagged vlan
- fdb:
  - mac and port
  - mac and status
  - clear: port, all
- flood fdb:
  - state, enable, disable
  - index, mac, timestamp
  - clear
- ipif:
  - name
- dhcp relay:
  - state, option82
  - ipif & servers
  - managing
- arp:
  - arp table
- port:
  - basic management: state, speed and duplex, flow control, address learning, mdix state, management
  - link, speed and duplex status
  - combo ports
  - cable diagnostics: action, pairs statuses and lengths
  - port security: state, max addresses, mode, management, clear by port/exact mac
  - loopback detection: status, enable, disable
  - port utilization
  - bandwidth control: rx, tx, management
  - traffic control: threshold, broadcast/multicast/unicast, action, count, interval, management
  - traffic segmentation: forward portlist, management
  - crc: alingment and fcs errors
  - packet: rx/tx bytes and unicast/multicast/broadcast packets
- ? log
- ? ping 8.8.8.8/another IP (may be unavailable)

# Справочник

## Trusted host

### Команды
- **create**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.4.1.171.12.1.2.10.1.1.2.4 a [IP] 1.3.6.1.4.1.171.12.1.2.10.1.1.4.4 a [MASK] 1.3.6.1.4.1.171.12.1.2.10.1.1.3.4 i 4`
- **delete**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.4.1.171.12.1.2.10.1.1.3.4 i 6`
- **delete all**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.4.1.171.12.1.2.10.2.0 i 2`

## Access profile
### Packet Content Frame Filter
1. Правила ACL для входящего (ingress) трафика с access-порта применяются сразу при поступлении пакета на порт. На основании решения после проверки с помощью ACL пакету добавляется тег PVID, и он проходит обработку таблицей коммутации. Следовательно, 4 байта 801.2Q-header при обработке ACL на пользовательском порту не добавляются.
2. Общая маска в Profile ID указывает на то, какие биты из полного Ethetnet-кадра нужно проверять, остальные просто пропускаются. На DES-3028 маска задаётся полным указанием байтовых масок для всей структуры кадра, на DGS-1210 можно указать несколько user-defined fields - конкретных фрагментов, определяемых смещением и маской.
3. Смещение offset/chunknumber задаёт смещение относительно начала кадра, с какого места проверять содержимое пакета: накладывать внутреннюю маску при необходимости и сравнивать с полезной нагрузкой. На DES-3028 настраивается через offset, на DGS-1210 offset=chunknumber*4 (chunknumber определяет блоки по 4 байта). На моделях DGS-1210, DGS-3120, DGS-3000 для обработки больших пакетов была реализована циклическая логика, когда байты 127 и 128 помещаются в начало буфера. То есть начальный блок (chunk 0) включает байты 127, 128, 1, 2. Для остальных chunk смещение идёт на +2 байта при сравнении со смещением на DES-3028.
4. Маска в Access ID (на DES-3028 не настраивается, настраивается только смещением offset по числу байт) показывает, какие именно байты/биты в рамках уже взятого блока проверять - это чуть более узкая спецификация.
5. Payload (Filter Value) в Access ID - значение, с которым побитово будет сравниваться полученный кусок. Сравниваются только те байты/биты, которые были вычленены с помощью масок и содержатся в самой полезной нагрузке, остальные пропускаются.

## VLAN
### Команды на DES-3028 (vlanid=2)
- **create**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.2.1.17.7.1.4.3.1.1.2 s VLAN2 1.3.6.1.2.1.17.7.1.4.3.1.5.2 i 4`
- **egress**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.2.1.17.7.1.4.3.1.2.2 x 00001000`
- **untagged**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.2.1.17.7.1.4.3.1.4.2 x 00001000`
- **none**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.2.1.17.7.1.4.3.1.2.2 x 00000000`
- **rename**: удалить -> создать с новым именем -> вернуть настройки для портов
- **delete**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.2.1.17.7.1.4.3.1.5.2 i 6`

### Комбинации запросов
| Текущий статус на порту | Запрос и тип OID | Итоговый статус на порту |
|-|-|-|
| none | `none(egress)` | none |
| none | `none(untagged)` | none |
| none | `egress` | tagged |
| none | `untagged` | untagged |
| tagged | `none(egress)` | none |
| tagged | `none(untagged)` | tagged |
| tagged | `egress` | tagged |
| tagged | `untagged` | untagged |
| untagged | `none(egress)` | none |
| untagged | `none(untagged)` | tagged |
| untagged | `egress` | untagged |
| untagged | `untagged` | untagged |

## DHCP relay

### Механизм работы
1. Клиентское устройство на порту коммутатора (ему назначен определённый VLAN ID) отправляет broadcast-запрос DHCP DISCOVER.
2. Первый коммутатор в сети, на котором включён DHCP RELAY, перехватывает пакет.
3. Если настройки ipif и VLAN на коммутаторе соответствуют клиентскому порту, то пакет будет успешно обработан и в поле ipif отправителя (giaddr) будет указан IP-адрес нужного интерфейса. Иначе будет отброшен.
4. Если на коммутаторе включено Option82 State, то в пакете будут указаны два дополнительных поля:
   - Remote ID - идентификатор удалённого relay-устройства, по умолчанию MAC-адрес коммутатора.
   - Circuit ID - идентификатор цепи, по умолчанию включающий VLAN ID и номер порта, с которого получен запрос.
5. Если на коммутаторе включена Option82 Check, то при наличии в клиентском запросе собственного поля Option82 он будет отброшен. Также неверные ответы от DHCP-сервера будут отброшены.
6. Если на коммутаторе выключена Option82 Check, в силу вступает настройка Option82 Policy:
   - replace - выставить свою Option82 в пакете (заменить при наличии клиентской);
   - drop - отбросить пакет при наличии клиентской Option82;
   - keep - сохранить пакет при наличии клиентской Option82.
7. На основании запроса и применённых настроек формируется unicast-пакет на каждый из назначенных DHCP-серверов. Hop count задаёт максимальное число хопов через relay-агенты до уничтожения пакета. Time threshold определяет задержку перед отправкой unicast-пакета DHCP-серверу (может быть полезно при работе DHCP LOCAL RELAY).
8. Relay-агент коммутатора обрабатывает ответ сервера и направляет клиенту.
9. Особенности обработки пакетов на разных моделях:
   - DES-3028 (функции настройки через VLAN ID имеют баги, не используются), DES-3200-28, DGS-3200-24 - на единственный ipif System должно быть назначено от 1 до 4 DHCP-серверов. Все клиентские запросы во всех VLAN будут обработаны при наличии такой записи, в качестве giaddr будет указан адрес ipif System (IP коммутатора). Circuit ID здесь всегда работает по умолчанию, изменить невозможно.
   - DGS-1210-28/ME - giaddr всегда будет соответствовать адресу системного ipif System, но пересылка сработает только для тех пользователей, чьи порты и VLAN явно прописаны в DHCP RELAY. Настройка трёх опций Option82 Policy индивидуальна для каждого порта.
   - DGS-3120-24TC, DGS-3000-24TC - возможна одновременная настройка DHCP RELAY через ipif и VLAN. В первую очередь проверяется настройка сегмента ipif: если VLAN пользователя относится к ipif коммутатора, для которого прописаны DHCP-сервера, то запросы адресуются им, в качестве giaddr используется адрес этого ipif. В противном случае используется настройка сегмента VLAN ID: если VLAN ID пользователя указан для каких-то DHCP-серверов, то запросы пересылаются им, в качестве ipif указывается адрес основного (Primary) ipif, соответствующего этому VLAN ID. Настройка Option82 аналогична модели DES-3028, но Circuit ID модифицируем.

### Команды на DES-3028
- **create (ipif System)**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.4.1.171.12.42.3.1.1.3.6.83.121.115.116.101.109.[dhcp_server] i 4`
- **create (user ipif)**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.4.1.171.12.42.3.1.1.3.[ipif_name_in_oid].[dhcp_server] i 4`
- **delete (ipif System)**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.4.1.171.12.42.3.1.1.3.6.83.121.115.116.101.109.[dhcp_server] i 6`
- **delete (user ipif)**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.4.1.171.12.42.3.1.1.3.[ipif_name_in_oid].[dhcp_server] i 6`

## Port security
### Команды на DES-3028 (port=21)
- **почистить определённый мак**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.4.1.171.11.63.6.2.15.3.1.0 s "[VLAN_NAME]" 1.3.6.1.4.1.171.11.63.6.2.15.3.2.0 i 21 1.3.6.1.4.1.171.11.63.6.2.15.3.3.0 x "[MAC ADDRESS]" 1.3.6.1.4.1.171.11.63.6.2.15.3.4.0 i 2`
- **дёрнуть lock address mode (deleteOnTimeout -> deleteOnReset -> deleteOnTimeout) для очистки маков на порту**: `snmpset -v2c -c [SNMP_READ_WRITE] [SNMP_TEST_3028] 1.3.6.1.4.1.171.11.63.6.2.15.1.1.3.21 i 4 1.3.6.1.4.1.171.11.63.6.2.15.1.1.3.21 i 3`
