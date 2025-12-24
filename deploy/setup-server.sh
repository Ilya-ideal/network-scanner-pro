#!/bin/bash
# setup-server.sh - Автоматическая настройка сервера для Network Scanner
# Использование: sudo bash setup-server.sh

set -e  # Выход при ошибках

echo "========================================"
echo "  Настройка Network Scanner Pro Server"
echo "  IP: 10.0.9.62"
echo "========================================"

# 1. Обновление системы
echo "[1/7] Обновление системы..."
apt-get update
apt-get upgrade -y

# 2. Установка базовых пакетов
echo "[2/7] Установка базовых пакетов..."
apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    nginx \
    ufw \
    nmap \
    arp-scan \
    sqlite3 \
    git \
    curl \
    htop \
    nload

# 3. Настройка брандмауэра
echo "[3/7] Настройка брандмауэра..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow from 10.0.9.0/24 to any port 8000 comment 'Local network scanner'
ufw --force reload

# 4. Создание пользователя и директорий
echo "[4/7] Создание пользователя и директорий..."
if ! id "network-scanner" &>/dev/null; then
    useradd -r -s /bin/bash -m -d /opt/network-scanner network-scanner
fi

mkdir -p /opt/network-scanner/{data,logs,backups,static/uploads}
chown -R network-scanner:network-scanner /opt/network-scanner
chmod 755 /opt/network-scanner

# 5. Копирование проекта (предполагается, что файлы уже в /tmp/network-scanner)
echo "[5/7] Копирование файлов проекта..."
if [ -d "/tmp/network-scanner" ]; then
    cp -r /tmp/network-scanner/* /opt/network-scanner/
    chown -R network-scanner:network-scanner /opt/network-scanner/*
else
    echo "⚠  Папка /tmp/network-scanner не найдена"
    echo "   Скопируйте файлы проекта вручную в /opt/network-scanner"
fi

# 6. Настройка Python окружения
echo "[6/7] Настройка Python окружения..."
sudo -u network-scanner bash -c "
    cd /opt/network-scanner
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
"

# 7. Настройка сервисов
echo "[7/7] Настройка сервисов..."

# Nginx
cp /opt/network-scanner/deploy/nginx.conf /etc/nginx/sites-available/network-scanner
ln -sf /etc/nginx/sites-available/network-scanner /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx

# Systemd сервис
cp /opt/network-scanner/deploy/network_scanner.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable network-scanner.service
systemctl start network-scanner.service

# 8. Финальная проверка
echo "========================================"
echo "  Настройка завершена!"
echo "  Проверяем сервисы..."
echo "========================================"

sleep 2

echo "✓ Systemd сервис:"
systemctl status network-scanner.service --no-pager -l

echo ""
echo "✓ Nginx:"
systemctl status nginx --no-pager -l

echo ""
echo "✓ Доступность API:"
curl -s -o /dev/null -w "HTTP статус: %{http_code}\n" http://localhost:8000/api/stats || echo "API недоступно"

echo ""
echo "========================================"
echo "  Доступ к интерфейсу:"
echo "  • http://10.0.9.62"
echo "  • http://10.0.9.62/api/stats"
echo "  • http://10.0.9.62/api/free-ips"
echo ""
echo "  Команды управления:"
echo "  • sudo systemctl status network-scanner"
echo "  • sudo journalctl -u network-scanner -f"
echo "  • sudo tail -f /opt/network-scanner/logs/scanner.log"
echo "========================================"