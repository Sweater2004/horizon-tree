============================================================
 HORIZON TREE v5.0
 Система мониторинга сети с авто-построением топологии
============================================================

Astra Linux · Python 3.11 · FastAPI · SQLite · vis-network

------------------------------------------------------------
 СОДЕРЖАНИЕ
------------------------------------------------------------
1. Возможности
2. Установка
3. Запуск
4. Использование
5. Структура проекта
6. API
7. Настройки
8. Устранение неполадок
9. FAQ

------------------------------------------------------------
 1. ВОЗМОЖНОСТИ
------------------------------------------------------------

СКАНИРОВАНИЕ СЕТИ
- ARP-скан (arp-scan, ip neigh) — поиск устройств в L2-сегменте
- ICMP-скан (fping, nmap) — поиск устройств по ping
- Nmap — TCP-пинг (обходит ICMP-блокировки), определение MAC
- Traceroute — построение путей до устройств (включая скрытые хопы)
- SNMP — опрос sysName, sysDescr, sysUptime, sysLocation
- LLDP — определение соседей коммутаторов по SNMP
- SSH/TLS-отпечатки — склейка IP по одинаковым ключам/сертификатам

АВТО-ПОСТРОЕНИЕ ТОПОЛОГИИ
- Цепочки из traceroute (родитель -> ребёнок)
- Склейка по MAC — несколько IP с одним MAC = одно устройство
- Склейка по traceroute — прямые IP (без промежуточных) = один роутер
- LLDP-связи — достоверные связи между коммутаторами
- Исключение мёртвых IP — недоступные узлы не попадают в граф
  (кроме тех, у кого есть "живые братья" по MAC)

ВИЗУАЛИЗАЦИЯ
- Интерактивный граф сети (vis-network)
- Цветные линии по доступности целевого узла:
    зелёные — online
    красные — offline
    жёлтые — mixed
    серые — unknown
- Иконки устройств (PNG: router, switch, server, pc, firewall, cloud)
- Цветной круг вокруг иконки по статусу
- Tooltip при наведении — IP, тип, статус, порт
- Дерево слева — иерархия узлов
- Модалка свойств — тип, статус, проверки, интерфейсы, история

МОНИТОРИНГ
- Планировщик — проверки каждые 30 сек
- Все интерфейсы узла проверяются (не только первый IP)
- ICMP / TCP / UDP / SNMP — все методы
- Агрегация статуса:
    online  — все IP живы
    offline — все IP мертвы
    mixed   — часть IP жива
    unknown — нет данных
- История проверок — график latency, uptime, offline за 1ч/24ч/7д/30д
- Статистика по карте в шапке:
    Всего узлов
    Online / Mixed / Offline
    Uptime за 24ч

ПОЛЬЗОВАТЕЛИ
- 3 роли: admin / editor / viewer
- JWT-авторизация
- Блокировка пользователей
- Аудит-логи — кто что делал

КАРТЫ
- Создание / редактирование / удаление карт
- Версионирование — история изменений с откатом
- Публичный доступ — карта видна всем
- Соавторы — доступ с правами view/edit
- Экспорт / импорт — JSON
- Whitelist подсетей — ограничение сканирования

РУЧНОЕ РЕДАКТИРОВАНИЕ
- Добавить узел — IP, имя, тип, родитель, проверки
- Редактировать узел — IP, имя, тип, иконка, родитель
- Удалить узел — с каскадным удалением рёбер
- Связать два корня — объединение сегментов (VPN, cable, router, direct)
- Объединить устройства — несколько IP -> одно устройство
- Изменить интерфейсы — список IP-портов устройства
ОБЪЕДИНЕНИЕ КАРТ (КОМПОЗИЦИЯ)
- Создание композиции — объединение нескольких карт в одну общую (кнопка «Объединить карты» в меню).
- Контейнеры — каждая исходная карта отображается на графе в виде круга с названием и количеством устройств.
- Статусы контейнеров — цвет круга зависит от состояния устройств внутри карты:
    🟢 зелёный  — все устройства внутри онлайн
    🟠 оранжевый — часть устройств онлайн, часть offline (mixed)
    🔴 красный   — все устройства внутри offline
    🟣 фиолетовый — нет данных или карта пуста
- Ручное связывание — можно соединять контейнеры между собой линиями (CABLE / FIBER / RADIO / VPN / DIRECT):
    - клик по контейнеру → кнопка «Связать с другой картой»;
    - выбор целевой карты, типа связи и примечания;
    - связь отображается пунктирной линией с подписью типа;
    - удаление связи — правый клик по линии.
- Добавление карты в композицию — кнопка «Добавить карту сюда» в меню (для уже созданной композиции).
- Переход внутрь карты — кнопка «Перейти внутрь карты» в модалке контейнера (или клик по контейнеру).
- Авто-обновление — статусы контейнеров обновляются каждые 5 секунд без перезагрузки страницы.
GUI-ЛАУНЧЕР (PyQt5)
- Запуск / остановка сервера
- Настройка хоста и порта
- Логи в реальном времени (stdout + stderr в одном окне)
- Кнопка "Открыть в браузере"
- Сохранение настроек (gui_config.json)

------------------------------------------------------------
 2. УСТАНОВКА
------------------------------------------------------------

2.1. Системные зависимости

    sudo apt update
    sudo apt install -y python3.11 python3.11-venv python3-pip \
        arp-scan fping nmap traceroute snmp iproute2 iputils-ping \
        python3-pyqt5

2.2. Права на сетевые утилиты

    sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/arp-scan
    sudo setcap cap_net_raw+ep /usr/bin/ping

2.3. Python-окружение

    cd ~/projects/horizon_tree
    python3.11 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install fastapi uvicorn bcrypt pyjwt pyqt5

2.4. Иконки (опционально)

    Скачай PNG в static/icons/:
        router.png, switch.png, server.png, pc.png, firewall.png, cloud.png

    Где взять:
        https://icons8.com/icons/set/router
        https://mono-stockers.net/
        https://github.com/redhat-cop/ansible-icons

------------------------------------------------------------
 3. ЗАПУСК
------------------------------------------------------------

3.1. Через GUI (PyQt5)

    cd ~/projects/horizon_tree
    source venv/bin/activate
    python gui.py

    В окне:
        - Кнопка "Запустить" — запускает сервер
        - Настройки Хост / Порт — можно изменить
        - Логи — в реальном времени
        - "Браузер" — открывает UI

3.2. Через терминал (для отладки)

    cd ~/projects/horizon_tree
    source venv/bin/activate
    python app.py

    Сервер: http://<IP>:8000
    Пароль админа: admin_password.txt

3.3. Systemd (автозапуск)

    sudo cp horizon-tree.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now horizon-tree
    sudo journalctl -u horizon-tree -f

------------------------------------------------------------
 4. ИСПОЛЬЗОВАНИЕ
------------------------------------------------------------

4.1. Первый вход

    - Открой http://localhost:8000
    - Логин: admin
    - Пароль: cat admin_password.txt
    - Смени пароль через админку (/admin)

4.2. Создание карты

    - "Новая карта" -> название -> "Создать"
    - Укажи whitelist подсетей (например, 192.168.178.0/24)

4.3. Сканирование

    - "Сканировать" -> введи корневой IP (шлюз)
    - Укажи hops (глубина traceroute)
    - Отметь SNMP-обогащение (если нужно)
    - Жми "Сканировать"

    Что происходит:
        1. ARP + ICMP + Nmap -> находит устройства
        2. Проверка живости -> отсеивает мёртвые
        3. SNMP + LLDP -> обогащает метаданными
        4. Traceroute -> строит пути
        5. Склейка -> объединяет IP одного устройства
        6. Сохранение -> карта готова

4.4. Редактирование

    - Клик по узлу -> модалка свойств
    - "Редактировать" -> IP, имя, тип, иконка, родитель
    - "Изменить интерфейсы" -> список IP-портов
    - "История" -> график проверок
    - "Удалить" -> удалить узел

4.5. Автообновление

    Включено по умолчанию. Интервал адаптивный:
        <= 30 узлов   ->  5 сек
        31-50         -> 10 сек
        51-100        -> 15 сек
        101-200       -> 30 сек
        200+          -> 60 сек

------------------------------------------------------------
 5. СТРУКТУРА ПРОЕКТА
------------------------------------------------------------

horizon_tree/
    app.py                    FastAPI (роуты, сканирование)
    gui.py                    PyQt5-лаунчер
    db_conn.py                SQLite (WAL + retry)
    state.py                  ACTIVE_MAP_ID (для планировщика)
    ifmap.py                  Склейка по SSH/TLS-отпечаткам
    admin_password.txt        Пароль админа (генерируется)
    monitor.db                SQLite-база
    gui_config.json           Настройки GUI
    start.sh                  Запуск через терминал
    horizon-tree.service      Systemd-служба

    checks/
        __init__.py           run_check (icmp/tcp/udp/snmp)
        icmp.py               ICMP (ping)
        tcp.py                TCP (connect)
        udp.py                UDP (send/recv)
        scheduler.py          Планировщик (30 сек)

    scanner/
        arp_scan.py           ARP + ICMP + Nmap
        traceroute.py         Traceroute (с скрытыми хопами)
        topology_builder.py   Построение графа
        snmp_walk.py          SNMP + LLDP
        auto_detect.py        Автоопределение типа
        fingerprint.py        SSH/TLS отпечатки

    db/
        migrations.py         Миграции v5.0 + v6.0

    templates/
        index.html            Основной UI
        login.html            Логин
        admin.html            Админка

    static/
        style/                CSS (style.css, login.css, admin.css)
        js/                   JS (main.js, login.js, admin.js, ...)
        icons/                PNG-иконки
        favicon.svg

------------------------------------------------------------
 6. API
------------------------------------------------------------

Полная документация: http://<IP>:8000/docs (Swagger UI)

АУТЕНТИФИКАЦИЯ
    POST   /api/auth/login              Логин -> JWT-токен
    GET    /api/auth/me                 Текущий пользователь
    POST   /api/auth/logout             Выход

КАРТЫ
    GET    /api/maps                    Список карт
    POST   /api/maps                    Создать карту
    GET    /api/maps/{id}               Получить карту
    PUT    /api/maps/{id}               Обновить карту
    DELETE /api/maps/{id}               Удалить карту
    POST   /api/maps/{id}/activate      Сделать активной (для планировщика)
    GET    /api/maps/{id}/stats         Статистика (online/offline/uptime)
    GET    /api/maps/{id}/versions      История версий
    POST   /api/maps/{id}/versions/{v}/restore   Откатить
    GET    /api/maps/{id}/export        Экспорт JSON
    POST   /api/maps/import             Импорт JSON

СКАНИРОВАНИЕ
    POST   /api/maps/{id}/scan          Запустить сканирование
    GET    /api/maps/{id}/scan/{job_id} Статус сканирования

УЗЛЫ
    POST   /api/maps/{id}/nodes         Добавить узел
    PUT    /api/maps/{id}/nodes/{nid}   Изменить узел
    DELETE /api/maps/{id}/nodes/{nid}   Удалить узел
    PUT    /api/maps/{id}/nodes/{nid}/interfaces   Изменить интерфейсы
    PUT    /api/maps/{id}/nodes/{nid}/checks       Изменить проверки
    PUT    /api/maps/{id}/nodes/{nid}/icon         Изменить иконку
    GET    /api/maps/{id}/nodes/{nid}/history      История проверок

СВЯЗИ
    POST   /api/maps/{id}/link-roots    Связать два корня
    POST   /api/maps/{id}/devices/merge Объединить устройства

АДМИНКА
    GET    /api/admin/users             Список пользователей
    POST   /api/admin/users             Создать пользователя
    PUT    /api/admin/users/{id}        Изменить пользователя
    DELETE /api/admin/users/{id}        Удалить пользователя
    GET    /api/admin/settings          Глобальные настройки
    PUT    /api/admin/settings          Обновить настройки

------------------------------------------------------------
 7. НАСТРОЙКИ
------------------------------------------------------------

7.1. Глобальные (таблица global_settings)

    allowed_subnets          Whitelist подсетей
                             По умолчанию: ["192.168.178.0/24"]
    snmp_default_community   SNMP community (по умолчанию "public")
    snmp_default_version     SNMP версия (по умолчанию "2c")
    scan_timeout             Таймаут сканирования (сек, по умолчанию 5)
    max_hops                 Макс. глубина traceroute (по умолчанию 10)
    max_devices_per_scan     Макс. устройств (по умолчанию 500)

7.2. На карте (таблица network_maps)

    allowed_subnets          Whitelist для этой карты
    data                     JSON-граф (nodes, edges)
    current_version          Текущая версия

7.3. GUI (gui_config.json)

    {
      "host": "127.0.0.1",
      "port": 8000
    }

7.4. Переменные окружения

    JWT_SECRET               Секрет для JWT (по умолчанию dev)
    HORIZON_HOST             Хост сервера
    HORIZON_PORT             Порт сервера

------------------------------------------------------------
 8. УСТРАНЕНИЕ НЕПОЛАДОК
------------------------------------------------------------

8.1. "database is locked"

    Решено в db_conn.py:
        WAL-режим
        timeout=30 + busy_timeout=30000
        Retry (3 попытки x 1 сек)
        BEGIN IMMEDIATE для записи

    Если всё равно — проверь:
        grep -rn "sqlite3.connect" . --include="*.py"
        (не должно быть в app.py/scheduler.py)

8.2. arp-scan запрашивает пароль

    sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/arp-scan
    getcap /usr/sbin/arp-scan

    Или — sudoers:
        sudo visudo -f /etc/sudoers.d/horizon-tree
        is ALL=(ALL) NOPASSWD: /usr/sbin/arp-scan

8.3. Планировщик не работает

    sudo journalctl -u horizon-tree -f | grep Планировщик

    Должно быть: "Планировщик проверок запущен (интервал 30с)"

8.4. Все узлы offline

    Проверь:
        ping -c 1 <IP>

    Если ICMP не проходит — сервер в другой сети.
    Это нормально — устройства в другой подсети без маршрута.

    Решение:
        - Добавь маршрут между сетями
        - Запусти мониторинг на сервере в той же сети
        - Используй SNMP (если доступен)

8.5. Сброс пароля админа

    cd ~/projects/horizon_tree
    source venv/bin/activate
    python -c "
    from app import DB_PATH, hash_password
    import sqlite3
    new_pass = 'новый-пароль'
    conn = sqlite3.connect(DB_PATH)
    conn.execute(\"UPDATE users SET password_hash = ? WHERE username = 'admin'\",
                 (hash_password(new_pass),))
    conn.commit()
    print('Пароль обновлён')
    "

8.6. Бэкап БД

    WAL-режим — копируй все 3 файла:
        cp monitor.db monitor.db-wal monitor.db-shm /backup/

------------------------------------------------------------
 9. FAQ
------------------------------------------------------------

В: Как добавить свою иконку?
О: 1. Положи PNG в static/icons/ (например, my-router.png)
   2. В templates/index.html добавь:
      <div class="icon-option" data-icon="my-router">
          <img src="/static/icons/my-router.png">
      </div>
      в блок icon-picker
   3. Перезапусти сервер -> выбери иконку в модалке

В: Как склеить два IP в одно устройство?
О: Авто — при сканировании (MAC или traceroute)
   Ручное — "..." -> "Объединить устройства" -> выбери IP -> "Объединить"

В: Почему линии серые?
О: Серые — unknown (нет данных). Будут красными/зелёными
   после первой проверки (30 сек).

В: Как ограничить сканирование?
О: Whitelist подсетей:
   - Глобально: админка -> Settings
   - На карте: при создании / редактировании
   Устройства вне whitelist помечаются is_outside_whitelist=true.

В: Как экспортировать карту?
О: "..." -> "Экспорт" — скачается JSON.
   Импорт: "..." -> "Импорт" -> выбери файл.

В: Где хранятся пароли?
О: admin_password.txt — только для первого запуска.
   Дальше — хэш в БД (bcrypt).

В: Как обновить версию?
О: cd ~/projects/horizon_tree
   git pull
   source venv/bin/activate
   pip install -r requirements.txt
   sudo systemctl restart horizon-tree

============================================================
 ЛИЦЕНЗИЯ
============================================================
Внутренний проект Horizon. Все права защищены.

============================================================
 АВТОРЫ
============================================================
Horizon Tree — внутренняя разработка
Astra Linux — платформа

============================================================
Версия: 5.0
Дата: 2026
Платформа: Astra Linux · Python 3.11
============================================================
