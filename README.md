# AWG Web GUI

Веб-интерфейс для управления серверами **AmneziaWG 1.5 и 2.0** через Docker-контейнеры `amnezia-awg` / `amnezia-awg2`.

Позволяет из браузера добавлять серверы, синхронизировать существующие peers, управлять клиентами, генерировать конфигурации и QR-коды, смотреть мониторинг/трафик, запускать диагностику и работать с backup конфигов.

## Скриншот

![AWG Web GUI Clients View](https://raw.githubusercontent.com/sllikmll/awg-web-gui/main/docs/ui-clients.png)

## Возможности

- **Автоопределение настроек сервера** — версия AWG, контейнер, interface, config path, UDP port, subnet и DNS читаются из remote config.
- **Аутентификация по SSH-ключу или паролю** — можно использовать `/ssh/id_ed25519` из Docker volume или SSH password для dev/test.
- **Автосинхронизация существующих клиентов** — после добавления сервера GUI сразу импортирует peers из `wg0.conf` / `awg0.conf`.
- **Импорт private keys из `clientsTable`** — если Amnezia сохранила private key клиента, GUI подтянет его и включит config/QR export.
- **Ручное восстановление private key** — можно вставить private key в Edit client или импортировать существующий client `.conf`.
- **Управление клиентами** — добавление, редактирование, удаление, временное отключение/включение, QR-код и `.conf` export.
- **Мониторинг и учёт трафика** — online/offline, latest handshake, endpoint, RX/TX и накопительный traffic accounting.
- **SQLite backend** — основной источник данных `/data/awg-web-gui.db`; legacy JSON export остаётся только для debug/backup.
- **Docker deployment** — готовый Dockerfile, compose example и GHCR image.
- **Фоновое обновление metadata** — периодически обновляет subnet/port/DNS из remote config, не изменяя сам VPN config.
- **Health diagnostics** — проверка SSH, Docker container, runtime AWG, `ip_forward`, NAT и subnet mismatch.
- **Remote config backups** — backup перед изменениями, просмотр backup-файлов и restore из UI.
- **Fleet import** — импорт списка серверов JSON array с auto-detect AWG 1.5/2.0 и auto-sync peers.
- **Журнал событий** — sync, polling, ошибки, import, restore и другие операции пишутся в `events`.
- **Security cleanup** — password hashing через Werkzeug, смена пароля в UI, секреты маскируются в публичных API ответах.
- **Веб-интерфейс** — простой адаптивный UI для всех операций.

## Требования

- Python 3.10+
- Docker на сервере, где запускается GUI.
- SSH-доступ к AWG-серверам.
- На целевом AWG-сервере должен быть запущен Docker-контейнер:
  - AWG 1.5: `amnezia-awg`, interface `wg0`, config `/opt/amnezia/awg/wg0.conf`;
  - AWG 2.0: `amnezia-awg2`, interface `awg0`, config `/opt/amnezia/awg/awg0.conf`.

## Быстрый запуск через Docker

```bash
git clone https://github.com/sllikmll/awg-web-gui.git
cd awg-web-gui
cp docker-compose.example.yml docker-compose.yml
mkdir -p data ssh
```

Положите SSH-ключ для доступа к AmneziaWG-серверам в `./ssh/`:

```bash
cp ~/.ssh/id_ed25519 ./ssh/id_ed25519
chmod 600 ./ssh/id_ed25519
```

В `docker-compose.yml` замените `AWG_SECRET_KEY` на длинную случайную строку и запустите:

```bash
docker compose up -d --build
```

Web UI по умолчанию:

```text
http://127.0.0.1:8095
```

Логин по умолчанию:

```text
admin / admin
```

> ⚠️ После первого входа обязательно смените пароль и `AWG_SECRET_KEY`, если GUI доступен не только локально.

## Готовый GHCR image

После push в `main` GitHub Actions собирает образ:

```text
ghcr.io/sllikmll/awg-web-gui:latest
```

Пример compose:

```yaml
services:
  awg-web-gui:
    image: ghcr.io/sllikmll/awg-web-gui:latest
    container_name: awg-web-gui
    restart: unless-stopped
    environment:
      AWG_SECRET_KEY: "change-me-long-random-string"
      AWG_DATA_DIR: /data
      AWG_POLL_INTERVAL: "30"
      AWG_ONLINE_THRESHOLD: "180"
      AWG_METADATA_REFRESH_INTERVAL: "300"
    ports:
      - "8095:5173"
    volumes:
      - ./data:/data
      - ./ssh:/ssh:ro
```

## Конфигурация

| Переменная | По умолчанию | Описание |
| :--- | :---: | :--- |
| `AWG_SECRET_KEY` | `dev-change-me` | Flask secret key для session cookies |
| `AWG_DATA_DIR` | `~/awg-web-gui-data` | Директория с SQLite DB и legacy JSON export |
| `AWG_POLL_INTERVAL` | `30` | Интервал фонового polling, секунд |
| `AWG_ONLINE_THRESHOLD` | `180` | Сколько секунд после handshake клиент считается online |
| `AWG_METADATA_REFRESH_INTERVAL` | `300` | Как часто обновлять subnet/port/DNS из remote config |
| `AWG_ENABLE_POLLER` | `1` | `0` отключает background poller |
| `PORT` | `5173` | HTTP port внутри контейнера |

## Как пользоваться

### Добавление сервера

1. Нажмите **Добавить сервер**.
2. Укажите `name`, `host`, SSH user/port и SSH key или SSH password.
3. Оставьте auto-detect включённым.
4. GUI сам проверит AWG 2.0 и AWG 1.5 контейнеры.
5. Если найдены оба варианта, будут добавлены оба сервера.
6. После добавления автоматически выполнится sync existing peers.

При standard Docker volume `./ssh:/ssh:ro` путь к ключу внутри GUI обычно:

```text
/ssh/id_ed25519
```

Если случайно ввести host path вроде `/root/.ssh/id_ed25519`, приложение попробует автоматически сопоставить его с `/ssh/id_ed25519`.

### Синхронизация существующих peers

Кнопка **Sync** читает `[Peer]` blocks из remote config и импортирует их в SQLite.

GUI также пытается подтянуть private keys из Amnezia `clientsTable`, если они там есть.

### Private key существующих клиентов

WireGuard/AmneziaWG server config хранит только:

```ini
PublicKey = ...
PresharedKey = ...
AllowedIPs = ...
```

Client `PrivateKey` криптографически невозможно восстановить из `PublicKey`.

Поэтому для existing clients есть три варианта:

1. **clientsTable содержит private key** — GUI подтянет его автоматически при sync/enrich.
2. **private key известен пользователю** — вставьте его в **Edit client**.
3. **есть готовый client `.conf`** — используйте **Импорт .conf**.

Без private key GUI может показать peer и мониторинг, но не сможет сгенерировать рабочий config/QR.

### Добавление клиента

1. Выберите сервер.
2. Введите имя клиента.
3. IP можно оставить пустым — GUI сам выберет свободный адрес из subnet.
4. GUI создаст keypair/PSK, добавит peer в remote config, сделает restart только AWG-контейнера и проверит peer в runtime.

### Disable / Enable клиента

- **Disable** удаляет peer из remote config, но оставляет запись в SQLite и private key.
- **Enable** записывает peer обратно в remote config.

Это удобно для временного отключения устройства без потери config/QR.

### Diagnostics

Кнопка **Diagnose** проверяет:

- SSH и Docker container;
- наличие config file;
- runtime `wg/awg show`;
- host `net.ipv4.ip_forward`;
- NAT/MASQUERADE/SNAT rules;
- наличие subnet mismatch между server subnet и peer allowed IPs;
- количество runtime peers и online peers.

Типичный полезный warning:

```text
handshake/runtime peers exist, but NAT rules do not mention server subnet
```

Это значит, что peer может быть online, но traffic routing/NAT настроены не под ту subnet.

### Backups / Restore

Перед изменением remote config GUI создаёт backup:

```text
/opt/amnezia/awg/wg0.conf.bak-YYYYMMDD-HHMMSS
/opt/amnezia/awg/awg0.conf.bak-YYYYMMDD-HHMMSS
```

В UI можно:

- посмотреть последние backup-файлы;
- восстановить выбранный backup.

Перед restore GUI создаёт backup текущего config и рестартит только соответствующий AWG container.

### Fleet import

Откройте **Fleet import** и вставьте JSON array:

```json
[
  {
    "name": "admrus",
    "host": "127.0.0.1",
    "ssh_user": "root",
    "ssh_key": "/ssh/id_ed25519"
  },
  {
    "name": "admpol",
    "host": "127.0.0.1",
    "ssh_user": "root",
    "ssh_key": "/ssh/id_ed25519"
  }
]
```

Для каждого host GUI:

1. проверит AWG 2.0 и AWG 1.5;
2. добавит найденные серверы;
3. выполнит sync existing peers;
4. покажет summary.

## SQLite, мониторинг и traffic accounting

Основная база:

```text
/data/awg-web-gui.db
```

Таблицы:

| Таблица | Назначение |
| :--- | :--- |
| `servers` | добавленные AWG-серверы и параметры SSH/Docker |
| `clients` | клиенты/peers и данные для генерации config/QR |
| `users` | локальные пользователи GUI |
| `client_stats` | handshake, endpoint, online/offline, RX/TX, total RX/TX |
| `events` | журнал операций и ошибок |
| `settings` | служебные настройки |

Фоновый poller выполняет:

```bash
# AWG 1.5
docker exec amnezia-awg wg show wg0 dump

# AWG 2.0
docker exec amnezia-awg2 awg show awg0 dump
```

Счётчики WireGuard/AWG могут сбрасываться после restart контейнера. GUI хранит runtime counters и накопительные totals; если новый counter меньше предыдущего, это считается reset и новое значение добавляется как delta.

## Security notes

- Пароли пользователей хэшируются через Werkzeug; старый SHA256 admin hash поддерживается для backward compatibility.
- `ssh_password` не отдаётся обратно через `/api/servers`, только флаг `has_ssh_password`.
- `privkey` и `preshared_key` клиента не отдаются через `/api/clients`, только флаги `has_privkey` / `has_preshared_key`.
- Для production используйте HTTPS reverse proxy и смените `admin/admin`.
- SSH password хранится в SQLite, если вы его используете. Для production лучше SSH key.
- Private client keys хранятся в SQLite plain text, чтобы можно было генерировать config/QR. Ограничьте доступ к `/data` и делайте backup аккуратно.

## Проверка

```bash
docker compose ps
docker logs --tail 50 awg-web-gui
curl -I http://127.0.0.1:8095/
```

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt pytest
AWG_ENABLE_POLLER=0 pytest -q
python app.py
```

## Лицензия

MIT
