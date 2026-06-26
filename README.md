# WireGuard Web GUI

Веб-интерфейс для управления обычными **WireGuard** серверами через Docker-контейнеры, в первую очередь `wg-easy`.

Проект сделан как vanilla WireGuard-аналог `awg-web-gui`: добавление серверов, синхронизация существующих peers, управление клиентами, генерация `.conf`/QR, мониторинг handshake/traffic, диагностика и backup remote config перед изменениями.

## Возможности

- **Auto-detect WireGuard сервера** — контейнер, interface, config path, UDP port, subnet и DNS читаются из remote config.
- **Default wg-easy профиль** — `container=wg-easy`, `interface=wg0`, `config=/etc/wireguard/wg0.conf`, `port=51820`.
- **SSH key/password auth** — можно использовать `/ssh/id_ed25519` из Docker volume или SSH password для dev/test.
- **Синхронизация существующих peers** — GUI импортирует `[Peer]` blocks из remote `wg0.conf`.
- **Управление клиентами** — add/edit/delete, disable/enable, `.conf` export и QR-code.
- **Мониторинг и трафик** — online/offline, latest handshake, endpoint, RX/TX и накопительный traffic accounting.
- **SQLite backend** — основной источник данных `/data/wg-web-gui.db`; JSON export остаётся для debug/backup.
- **Remote config backups** — перед изменением WireGuard config создаётся backup рядом с config file.
- **Diagnostics** — SSH, Docker container, `wg show`, `ip_forward`, NAT и subnet mismatch.
- **Fleet import** — JSON array серверов с auto-detect и auto-sync.

## Требования

- Python 3.10+ или Docker.
- SSH-доступ к WireGuard-серверу.
- На целевом сервере должен быть Docker-контейнер с WireGuard tools, обычно:

```text
container: wg-easy
interface: wg0
config: /etc/wireguard/wg0.conf
UDP port: 51820
```

> Если у тебя другой контейнер/путь/interface — после ручного добавления/редактирования можно указать свои значения.

## Быстрый запуск через Docker

```bash
git clone https://github.com/sllikmll/wg-web-gui.git
cd wg-web-gui
cp docker-compose.example.yml docker-compose.yml
mkdir -p data ssh
# Контейнер работает под UID 10001, поэтому bind-mounted SQLite dir должен быть writable.
# Если запускаешь от обычного пользователя, может понадобиться sudo.
chown 10001:100 data
```

Положи SSH-ключ для доступа к VPN-серверам в `./ssh/`:

```bash
cp ~/.ssh/id_ed25519 ./ssh/id_ed25519
chmod 600 ./ssh/id_ed25519
```

В `docker-compose.yml` замени `WG_SECRET_KEY` и запусти:

```bash
docker compose up -d --build
```

Web UI по умолчанию:

```text
http://127.0.0.1:8096
```

Логин по умолчанию:

```text
admin / admin
```

> ⚠️ Если панель доступна не только локально — сразу поменяй пароль и `WG_SECRET_KEY`. Да, бэкапы и секреты, всё как мы любим.

## Docker Compose пример

```yaml
services:
  wg-web-gui:
    image: ghcr.io/sllikmll/wg-web-gui:latest
    container_name: wg-web-gui
    restart: unless-stopped
    environment:
      WG_SECRET_KEY: "change-me-long-random-string"
      WG_DATA_DIR: /data
      WG_POLL_INTERVAL: "30"
      WG_ONLINE_THRESHOLD: "180"
      WG_METADATA_REFRESH_INTERVAL: "300"
    ports:
      - "8096:5173"
    volumes:
      - ./data:/data
      - ./ssh:/ssh:ro
```

## Конфигурация

| Переменная | По умолчанию | Описание |
|---|---:|---|
| `WG_SECRET_KEY` | `dev-change-me` | Flask secret key для session cookies |
| `WG_DATA_DIR` | `~/wg-web-gui-data` | Директория с SQLite DB и JSON export |
| `WG_POLL_INTERVAL` | `30` | Интервал фонового polling, секунд |
| `WG_ONLINE_THRESHOLD` | `180` | Сколько секунд после handshake клиент считается online |
| `WG_METADATA_REFRESH_INTERVAL` | `300` | Как часто обновлять subnet/port/DNS из remote config |
| `WG_ENABLE_POLLER` | `1` | `0` отключает background poller |
| `PORT` | `5173` | HTTP port внутри контейнера |

Для совместимости код ещё принимает старые `AWG_*` env vars, но для нового проекта используй `WG_*`.

## Как пользоваться

### Добавить сервер

1. Нажми **Добавить сервер**.
2. Укажи `name`, `host`, SSH user/port и SSH key или password.
3. Оставь auto-detect включённым.
4. GUI проверит `wg-easy`, прочитает `/etc/wireguard/wg0.conf`, определит subnet/port/DNS.
5. После добавления выполнится sync existing peers.

### Добавить клиента

1. Выбери сервер.
2. Введи имя клиента.
3. IP можно оставить пустым — GUI выберет следующий свободный из subnet.
4. GUI создаст keypair/PSK, добавит `[Peer]` в remote config, сделает backup и restart только WireGuard-контейнера.
5. После проверки peer появится в runtime `wg show`.

### Existing clients и private key

WireGuard server config хранит только:

```ini
[Peer]
PublicKey = ...
PresharedKey = ...
AllowedIPs = ...
```

Client `PrivateKey` невозможно восстановить из `PublicKey`. Поэтому для существующих клиентов:

1. Если private key известен — вставь его в **Edit client**.
2. Если есть готовый client `.conf` — используй **Импорт .conf**.
3. Без private key GUI покажет peer/мониторинг, но не сможет сгенерировать рабочий config/QR.

## Проверка/разработка

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt pytest
WG_ENABLE_POLLER=0 pytest -q
```

## Примечания

- Удаление сервера из UI удаляет только запись из базы панели, реальный сервер не трогается.
- Перед любым изменением remote config создаётся backup: `/etc/wireguard/wg0.conf.bak-YYYYMMDD-HHMMSS`.
- Disable клиента убирает peer из remote config, но оставляет запись и private key в SQLite.
- Enable записывает peer обратно.
