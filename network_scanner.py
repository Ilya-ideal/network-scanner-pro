#!/usr/bin/env python3
"""
Network Scanner Pro для Windows
Версия: 2.0 Windows Edition
"""

import os
import sys
import json
import time
import sqlite3
import logging
import threading
import subprocess
import ipaddress
import platform
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from contextlib import contextmanager

# Flask для веб-интерфейса
from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler

# Сканирование сети
import nmap
import netifaces

# Проверка ОС
if platform.system() != 'Windows':
    print("❌ Эта версия предназначена только для Windows!")
    sys.exit(1)

# Настройка логирования для Windows
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'scanner.log'), encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class Host:
    """Класс для представления хоста в сети"""
    ip: str
    mac: str = "Unknown"
    hostname: str = ""
    vendor: str = "Unknown"
    status: str = "unknown"
    os_info: str = ""
    first_seen: str = ""
    last_seen: str = ""
    last_response: str = ""
    ports: str = "[]"
    is_dhcp: bool = True
    dhcp_lease: str = ""
    custom_name: str = ""
    notes: str = ""
    group: str = "default"
    
    def to_dict(self) -> Dict:
        data = asdict(self)
        data['is_online'] = self.status == 'up'
        data['uptime'] = self.calculate_uptime()
        return data
    
    def calculate_uptime(self) -> str:
        if not self.last_response or self.status != 'up':
            return "0"
        try:
            last = datetime.fromisoformat(self.last_response)
            delta = datetime.now() - last
            hours = delta.seconds // 3600
            minutes = (delta.seconds % 3600) // 60
            return f"{hours}ч {minutes}м"
        except:
            return "0"

class WindowsNetworkScanner:
    """Сканер сети для Windows"""
    
    def __init__(self, config, database):
        self.config = config
        self.db = database
        self.nm = nmap.PortScanner()
        self.is_scanning = False
        
    def scan_network(self, network_cidr: str = None) -> Dict:
        """Сканирование сети для Windows"""
        if self.is_scanning:
            return {'status': 'error', 'message': 'Сканирование уже выполняется'}
        
        self.is_scanning = True
        start_time = time.time()
        
        try:
            network = network_cidr or self.config.get('network.cidr', '10.0.9.0/24')
            logger.info(f"Сканирование сети: {network}")
            
            # Метод 1: ARP кэш Windows
            arp_hosts = self._scan_windows_arp()
            
            # Метод 2: Ping sweep
            ping_hosts = self._ping_sweep(network)
            
            # Метод 3: Nmap (если установлен)
            nmap_hosts = self._nmap_scan(network)
            
            # Объединяем результаты
            all_hosts = self._merge_results(arp_hosts, ping_hosts, nmap_hosts)
            
            # Сохраняем в базу
            saved_count = 0
            for host_data in all_hosts:
                host = Host(
                    ip=host_data['ip'],
                    mac=host_data.get('mac', 'Unknown'),
                    hostname=host_data.get('hostname', ''),
                    vendor=host_data.get('vendor', 'Unknown'),
                    status=host_data.get('status', 'unknown'),
                    last_seen=datetime.now().isoformat(),
                    last_response=datetime.now().isoformat() if host_data.get('status') == 'up' else ''
                )
                
                if self.db.save_host(host):
                    saved_count += 1
            
            result = {
                'status': 'success',
                'message': f'Найдено устройств: {saved_count}',
                'hosts_found': saved_count,
                'scan_duration': f"{time.time() - start_time:.2f} сек",
                'network': network
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Ошибка сканирования: {e}")
            return {'status': 'error', 'message': str(e)}
        finally:
            self.is_scanning = False
    
    def _scan_windows_arp(self) -> List[Dict]:
        """Чтение ARP кэша Windows"""
        hosts = []
        try:
            # Команда arp -a в Windows
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                text=True,
                encoding='cp866',  # Кодировка для русского Windows
                timeout=10
            )
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and '---' not in line and 'Интерфейс' not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        mac = parts[1].replace('-', ':')
                        status = 'up'  # В ARP кэше только активные устройства
                        
                        # Пропускаем широковещательные адреса
                        if ip not in ['224.0.0.0', '255.255.255.255']:
                            hosts.append({
                                'ip': ip,
                                'mac': mac,
                                'status': status,
                                'source': 'windows-arp'
                            })
                            
        except Exception as e:
            logger.warning(f"Ошибка чтения ARP кэша: {e}")
        
        return hosts
    
    def _ping_sweep(self, network: str) -> List[Dict]:
        """Ping sweep для Windows"""
        hosts = []
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            
            # Сканируем первые 50 адресов (можно изменить)
            for i in range(1, 51):
                ip = str(network_obj.network_address + i)
                
                # Пинг для Windows
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                status = 'up' if result.returncode == 0 else 'down'
                
                if status == 'up':
                    # Пробуем получить имя хоста
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = ""
                    
                    hosts.append({
                        'ip': ip,
                        'status': status,
                        'hostname': hostname,
                        'source': 'windows-ping'
                    })
                    
        except Exception as e:
            logger.warning(f"Ошибка ping sweep: {e}")
        
        return hosts
    
    def _nmap_scan(self, network: str) -> List[Dict]:
        """Сканирование через Nmap (если установлен)"""
        hosts = []
        try:
            self.nm.scan(hosts=network, arguments='-sn -T4')
            
            for host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'status': self.nm[host].state(),
                    'source': 'nmap'
                }
                
                if 'addresses' in self.nm[host] and 'mac' in self.nm[host]['addresses']:
                    host_info['mac'] = self.nm[host]['addresses']['mac']
                    
                    if 'vendor' in self.nm[host]:
                        mac = self.nm[host]['addresses']['mac']
                        if mac in self.nm[host]['vendor']:
                            host_info['vendor'] = self.nm[host]['vendor'][mac]
                
                if self.nm[host].hostname():
                    host_info['hostname'] = self.nm[host].hostname()
                
                hosts.append(host_info)
                
        except Exception as e:
            logger.warning(f"Nmap сканирование недоступно: {e}")
        
        return hosts
    
    def _merge_results(self, *host_lists) -> List[Dict]:
        """Объединить результаты"""
        merged = {}
        for host_list in host_lists:
            for host in host_list:
                ip = host['ip']
                if ip in merged:
                    # Объединяем информацию
                    merged[ip].update({
                        k: v for k, v in host.items() 
                        if v and (k not in merged[ip] or not merged[ip][k])
                    })
                else:
                    merged[ip] = host
        return list(merged.values())
    
    def ping_host(self, ip: str) -> Dict:
        """Пинг отдельного хоста"""
        try:
            # Windows ping
            result = subprocess.run(
                ['ping', '-n', '2', '-w', '1000', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            is_online = result.returncode == 0
            
            # Обновляем статус в БД
            status = 'up' if is_online else 'down'
            self.db.update_host_info(
                ip, 
                status=status,
                last_response=datetime.now().isoformat() if is_online else ''
            )
            
            return {
                'status': 'success',
                'online': is_online,
                'message': f'Хост {ip} {"доступен" if is_online else "недоступен"}'
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

class Config:
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Ошибка загрузки конфигурации: {e}")
        
        # Конфигурация по умолчанию для Windows
        default_config = {
            'network': {'cidr': '10.0.9.0/24', 'interface': 'Ethernet'},
            'server': {'host': '10.0.9.172', 'port': 8000, 'debug': False},
            'scanner': {'scan_interval': 300, 'auto_scan': True}
        }
        self.save_config(default_config)
        return default_config
    
    def save_config(self, config=None):
        if config:
            self.config = config
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)
    
    def get(self, key, default=None):
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def init_database(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self.get_connection() as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    status TEXT,
                    os_info TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    last_response TEXT,
                    ports TEXT DEFAULT '[]',
                    is_dhcp INTEGER DEFAULT 1,
                    dhcp_lease TEXT,
                    custom_name TEXT,
                    notes TEXT,
                    host_group TEXT DEFAULT 'default'
                )
            ''')
            conn.commit()
    
    def save_host(self, host):
        try:
            with self.get_connection() as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT id FROM hosts WHERE ip = ?
                ''', (host.ip,))
                existing = c.fetchone()
                
                if existing:
                    c.execute('''
                        UPDATE hosts SET
                            mac = COALESCE(?, mac),
                            hostname = COALESCE(?, hostname),
                            vendor = COALESCE(?, vendor),
                            status = ?,
                            last_seen = ?,
                            last_response = ?
                        WHERE ip = ?
                    ''', (host.mac, host.hostname, host.vendor, 
                          host.status, host.last_seen, 
                          host.last_response, host.ip))
                else:
                    c.execute('''
                        INSERT INTO hosts (ip, mac, hostname, vendor, status, 
                                          first_seen, last_seen, last_response)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (host.ip, host.mac, host.hostname, host.vendor,
                          host.status, host.last_seen, host.last_seen, 
                          host.last_response))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка сохранения хоста: {e}")
            return False
    
    def get_all_hosts(self):
        try:
            with self.get_connection() as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT * FROM hosts 
                    ORDER BY 
                        CASE status 
                            WHEN 'up' THEN 1 
                            WHEN 'down' THEN 2 
                            ELSE 3 
                        END,
                        ip
                ''')
                return [dict(row) for row in c.fetchall()]
        except Exception as e:
            logger.error(f"Ошибка получения хостов: {e}")
            return []
    
    def update_host_info(self, ip, **kwargs):
        try:
            with self.get_connection() as conn:
                c = conn.cursor()
                fields = []
                values = []
                for key, value in kwargs.items():
                    if value is not None:
                        fields.append(f"{key} = ?")
                        values.append(value)
                values.append(ip)
                query = f"UPDATE hosts SET {', '.join(fields)} WHERE ip = ?"
                c.execute(query, values)
                conn.commit()
                return c.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка обновления хоста: {e}")
            return False
    
    def get_statistics(self):
        try:
            with self.get_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*) as total FROM hosts")
                total = c.fetchone()[0]
                c.execute("SELECT COUNT(*) as online FROM hosts WHERE status = 'up'")
                online = c.fetchone()[0]
                c.execute("SELECT COUNT(*) as offline FROM hosts WHERE status = 'down'")
                offline = c.fetchone()[0]
                return {
                    'total_hosts': total,
                    'online_hosts': online,
                    'offline_hosts': offline,
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            logger.error(f"Ошибка статистики: {e}")
            return {}

class WebInterface:
    def __init__(self, scanner, config, database):
        self.scanner = scanner
        self.config = config
        self.db = database
        
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        CORS(self.app)
        self.app.config['JSON_AS_ASCII'] = False
        self.register_routes()
    
    def register_routes(self):
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/api/hosts', methods=['GET'])
        def get_hosts():
            try:
                hosts = self.db.get_all_hosts()
                return jsonify({
                    'status': 'success',
                    'count': len(hosts),
                    'hosts': hosts
                })
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/stats', methods=['GET'])
        def get_stats():
            try:
                stats = self.db.get_statistics()
                return jsonify({'status': 'success', 'stats': stats})
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            try:
                data = request.get_json() or {}
                network = data.get('network') or self.config.get('network.cidr')
                
                def scan_task():
                    self.scanner.scan_network(network)
                
                thread = threading.Thread(target=scan_task)
                thread.daemon = True
                thread.start()
                
                return jsonify({
                    'status': 'success',
                    'message': 'Сканирование запущено'
                })
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/ping/<ip>', methods=['GET'])
        def ping_host(ip):
            try:
                result = self.scanner.ping_host(ip)
                return jsonify(result)
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/hosts/<ip>', methods=['PUT'])
        def update_host(ip):
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'status': 'error', 'message': 'Нет данных'}), 400
                
                updated = self.db.update_host_info(ip, **data)
                if updated:
                    return jsonify({'status': 'success', 'message': 'Обновлено'})
                else:
                    return jsonify({'status': 'error', 'message': 'Хост не найден'}), 404
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/export/csv', methods=['GET'])
        def export_csv():
            try:
                import csv
                import io
                
                hosts = self.db.get_all_hosts()
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=[
                    'ip', 'hostname', 'mac', 'vendor', 'status', 
                    'first_seen', 'last_seen'
                ])
                writer.writeheader()
                for host in hosts:
                    writer.writerow({
                        'ip': host['ip'],
                        'hostname': host['hostname'] or '',
                        'mac': host['mac'] or '',
                        'vendor': host['vendor'] or '',
                        'status': host['status'],
                        'first_seen': host['first_seen'],
                        'last_seen': host['last_seen']
                    })
                
                response = Response(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=network_hosts.csv'}
                )
                return response
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/static/<path:filename>')
        def static_files(filename):
            return send_file(f'static/{filename}')
        
        @self.app.route('/api/free-ips', methods=['GET'])
        def get_free_ips():
            try:
                # Получаем параметры из запроса
                network_cidr = request.args.get('network', self.config.get('network.cidr', '10.0.9.0/24'))
                
                # Получаем все хосты из БД
                all_hosts = self.db.get_all_hosts()
                used_ips = {host['ip'] for host in all_hosts}
                
                # Генерируем все IP-адреса в сети
                network = ipaddress.ip_network(network_cidr, strict=False)
                all_ips = [str(ip) for ip in network.hosts()]  # Все возможные адреса, кроме сетевого и широковещательного
                
                # Фильтруем свободные IP
                free_ips = [ip for ip in all_ips if ip not in used_ips]
                
                return jsonify({
                    'status': 'success',
                    'network': network_cidr,
                    'total_ips': len(all_ips),
                    'used_ips': len(used_ips),
                    'free_ips_count': len(free_ips),
                    'free_ips': free_ips[:200],  # Возвращаем только первые 200
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Ошибка получения свободных IP: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500

    def run(self):
        host = self.config.get('server.host', '10.0.9.172')
        port = self.config.get('server.port', 8000)
        debug = self.config.get('server.debug', False)
        
        print(f"\n{'='*50}")
        print("   Network Scanner Pro для Windows")
        print(f"{'='*50}")
        print(f"🌐 Веб-интерфейс: http://{host}:{port}")
        print(f"🔧 API: http://{host}:{port}/api/hosts")
        print(f"📊 Статистика: http://{host}:{port}/api/stats")
        print(f"{'='*50}\n")
        
        self.app.run(host=host, port=port, debug=debug, threaded=True)

def create_windows_templates():
    """Создание HTML/CSS/JS файлов для Windows"""
    
    # Создаем директории
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    # HTML файл
    html_content = '''<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scanner - 10.0.9.0/24</title>
    <link rel="stylesheet" href="/static/css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <header>
            <h1><i class="fas fa-network-wired"></i> Network Scanner для Windows</h1>
            <div class="network-info">
                <span>Сеть: 10.0.9.0/24</span>
                <span id="lastUpdate">Последнее обновление: --:--:--</span>
            </div>
        </header>
        
        <div class="stats">
            <div class="stat-card">
                <i class="fas fa-server"></i>
                <div>
                    <h3>Всего устройств</h3>
                    <p id="totalDevices">0</p>
                </div>
            </div>
            <div class="stat-card">
                <i class="fas fa-wifi"></i>
                <div>
                    <h3>Онлайн</h3>
                    <p id="onlineDevices">0</p>
                </div>
            </div>
            <div class="stat-card">
                <i class="fas fa-plug"></i>
                <div>
                    <h3>Оффлайн</h3>
                    <p id="offlineDevices">0</p>
                </div>
            </div>
            <div class="stat-card">
                <i class="fas fa-sync-alt"></i>
                <div>
                    <h3>DHCP</h3>
                    <p id="dhcpDevices">0</p>
                </div>
            </div>
        </div>
        
        <div class="controls">
            <button onclick="scanNetwork()" class="btn primary">
                <i class="fas fa-search"></i> Сканировать сеть
            </button>
            <button onclick="exportCSV()" class="btn secondary">
                <i class="fas fa-download"></i> Экспорт CSV
            </button>
            <button onclick="refreshData()" class="btn">
                <i class="fas fa-redo"></i> Обновить
            </button>
            <div class="search">
                <input type="text" id="searchInput" placeholder="Поиск по IP или имени...">
                <i class="fas fa-search"></i>
            </div>
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>IP Адрес</th>
                        <th>Имя</th>
                        <th>MAC Адрес</th>
                        <th>Производитель</th>
                        <th>Статус</th>
                        <th>Последний раз видели</th>
                        <th>Действия</th>
                    </tr>
                </thead>
                <tbody id="hostsTable">
                    <tr>
                        <td colspan="7" class="loading">
                            <i class="fas fa-spinner fa-spin"></i> Загрузка данных...
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
        
        <footer>
            <p>Network Scanner Pro для Windows | Автообновление каждые 60 секунд</p>
        </footer>
    </div>
    
    <script src="/static/js/app.js"></script>
</body>
</html>'''
    
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # CSS файл
    css_content = '''* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    background: white;
    border-radius: 10px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    overflow: hidden;
}

/* Header */
header {
    background: #2c3e50;
    color: white;
    padding: 20px 30px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
}

header h1 {
    font-size: 24px;
    display: flex;
    align-items: center;
    gap: 10px;
}

.network-info {
    display: flex;
    gap: 20px;
    font-size: 14px;
    opacity: 0.9;
}

/* Stats */
.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    padding: 30px;
    background: #f8f9fa;
}

.stat-card {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 3px 10px rgba(0,0,0,0.1);
    display: flex;
    align-items: center;
    gap: 15px;
    transition: transform 0.3s;
}

.stat-card:hover {
    transform: translateY(-5px);
}

.stat-card i {
    font-size: 32px;
    color: #3498db;
}

.stat-card h3 {
    font-size: 14px;
    color: #7f8c8d;
    margin-bottom: 5px;
}

.stat-card p {
    font-size: 28px;
    font-weight: bold;
    color: #2c3e50;
}

/* Controls */
.controls {
    padding: 20px 30px;
    background: white;
    border-bottom: 1px solid #eee;
    display: flex;
    gap: 15px;
    align-items: center;
    flex-wrap: wrap;
}

.btn {
    padding: 10px 20px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 500;
    transition: all 0.3s;
}

.btn.primary {
    background: #3498db;
    color: white;
}

.btn.primary:hover {
    background: #2980b9;
}

.btn.secondary {
    background: #95a5a6;
    color: white;
}

.btn.secondary:hover {
    background: #7f8c8d;
}

.search {
    flex-grow: 1;
    max-width: 300px;
    position: relative;
}

.search input {
    width: 100%;
    padding: 10px 15px 10px 40px;
    border: 2px solid #ddd;
    border-radius: 5px;
    font-size: 14px;
}

.search i {
    position: absolute;
    left: 15px;
    top: 50%;
    transform: translateY(-50%);
    color: #7f8c8d;
}

/* Table */
.table-container {
    padding: 30px;
}

table {
    width: 100%;
    border-collapse: collapse;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
}

thead {
    background: #3498db;
    color: white;
}

th {
    padding: 15px;
    text-align: left;
    font-weight: 500;
}

td {
    padding: 12px 15px;
    border-bottom: 1px solid #eee;
}

tr:hover {
    background: #f5f5f5;
}

.status {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: bold;
}

.status.online {
    background: #d4edda;
    color: #155724;
}

.status.offline {
    background: #f8d7da;
    color: #721c24;
}

.actions {
    display: flex;
    gap: 8px;
}

.action-btn {
    padding: 5px 10px;
    border: 1px solid #ddd;
    background: white;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.2s;
}

.action-btn:hover {
    background: #f8f9fa;
    border-color: #3498db;
}

.loading {
    text-align: center;
    padding: 40px;
    color: #7f8c8d;
}

/* Footer */
footer {
    padding: 20px;
    text-align: center;
    color: #7f8c8d;
    font-size: 14px;
    background: #f8f9fa;
    border-top: 1px solid #eee;
}

@media (max-width: 768px) {
    header {
        flex-direction: column;
        text-align: center;
        gap: 15px;
    }
    
    .controls {
        flex-direction: column;
        align-items: stretch;
    }
    
    .search {
        max-width: 100%;
    }
    
    .btn {
        width: 100%;
        justify-content: center;
    }
}'''
    
    with open('static/css/style.css', 'w', encoding='utf-8') as f:
        f.write(css_content)
    
    # JavaScript файл
    js_content = '''// Network Scanner для Windows - Frontend

class NetworkScanner {
    constructor() {
        this.apiBase = '/api';
        this.init();
    }

    init() {
        this.loadData();
        this.setupAutoRefresh();
        this.setupSearch();
    }

    async loadData() {
        await Promise.all([
            this.loadHosts(),
            this.loadStats()
        ]);
        this.updateLastUpdate();
    }

    async loadHosts() {
        try {
            const response = await fetch(`${this.apiBase}/hosts`);
            const data = await response.json();
            
            if (data.status === 'success') {
                this.renderHosts(data.hosts);
            }
        } catch (error) {
            console.error('Error loading hosts:', error);
            this.showError('Не удалось загрузить список устройств');
        }
    }

    renderHosts(hosts) {
        const table = document.getElementById('hostsTable');
        
        if (hosts.length === 0) {
            table.innerHTML = `
                <tr>
                    <td colspan="7" class="loading">
                        <i class="fas fa-inbox"></i>
                        <p>Устройства не найдены</p>
                    </td>
                </tr>
            `;
            return;
        }

        let html = '';
        hosts.forEach(host => {
            const statusClass = host.status === 'up' ? 'online' : 'offline';
            const statusText = host.status === 'up' ? 'ОНЛАЙН' : 'ОФФЛАЙН';
            
            const lastSeen = host.last_response ? 
                this.formatTime(new Date(host.last_response)) : 'Никогда';

            html += `
                <tr>
                    <td><strong>${host.ip}</strong></td>
                    <td>${host.hostname || 'Неизвестно'}</td>
                    <td><code>${host.mac || 'Неизвестно'}</code></td>
                    <td>${host.vendor || 'Неизвестно'}</td>
                    <td>
                        <span class="status ${statusClass}">
                            ${statusText}
                        </span>
                    </td>
                    <td>${lastSeen}</td>
                    <td>
                        <div class="actions">
                            <button class="action-btn" onclick="scanner.ping('${host.ip}')" title="Пинг">
                                <i class="fas fa-signal"></i>
                            </button>
                            <button class="action-btn" onclick="scanner.edit('${host.ip}')" title="Редактировать">
                                <i class="fas fa-edit"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });

        table.innerHTML = html;
        this.applySearch();
    }

    async loadStats() {
        try {
            const response = await fetch(`${this.apiBase}/stats`);
            const data = await response.json();
            
            if (data.status === 'success') {
                const stats = data.stats;
                document.getElementById('totalDevices').textContent = stats.total_hosts || 0;
                document.getElementById('onlineDevices').textContent = stats.online_hosts || 0;
                document.getElementById('offlineDevices').textContent = stats.offline_hosts || 0;
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    async scanNetwork() {
        const button = document.querySelector('.btn.primary');
        const originalText = button.innerHTML;
        
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Сканирование...';
        button.disabled = true;
        
        try {
            const response = await fetch(`${this.apiBase}/scan`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({network: '10.0.9.0/24'})
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showMessage('Сканирование запущено. Данные обновятся через несколько секунд.', 'success');
                
                setTimeout(() => {
                    this.loadData();
                }, 3000);
            } else {
                this.showMessage(data.message || 'Ошибка сканирования', 'error');
            }
        } catch (error) {
            this.showMessage('Не удалось запустить сканирование', 'error');
            console.error('Error:', error);
        } finally {
            setTimeout(() => {
                button.innerHTML = originalText;
                button.disabled = false;
            }, 2000);
        }
    }

    async ping(ip) {
        try {
            const response = await fetch(`${this.apiBase}/ping/${ip}`);
            const data = await response.json();
            
            if (data.status === 'success') {
                const message = data.online ? 
                    `Хост ${ip} доступен` : 
                    `Хост ${ip} недоступен`;
                const type = data.online ? 'success' : 'warning';
                
                this.showMessage(message, type);
                setTimeout(() => this.loadHosts(), 1000);
            }
        } catch (error) {
            this.showMessage(`Ошибка пинга ${ip}`, 'error');
        }
    }

    edit(ip) {
        const newName = prompt(`Введите новое имя для ${ip}:`, '');
        if (newName !== null) {
            this.updateHost(ip, {custom_name: newName});
        }
    }

    async updateHost(ip, data) {
        try {
            const response = await fetch(`${this.apiBase}/hosts/${ip}`, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            if (result.status === 'success') {
                this.showMessage('Информация обновлена', 'success');
                this.loadHosts();
            }
        } catch (error) {
            this.showMessage('Ошибка обновления', 'error');
        }
    }

    async exportCSV() {
        try {
            const response = await fetch(`${this.apiBase}/export/csv`);
            const blob = await response.blob();
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `network_${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            this.showMessage('Экспорт завершен', 'success');
        } catch (error) {
            this.showMessage('Ошибка экспорта', 'error');
        }
    }

    refreshData() {
        this.loadData();
        this.showMessage('Данные обновлены', 'info');
    }

    setupAutoRefresh() {
        setInterval(() => {
            this.loadData();
        }, 60000); // 60 секунд
    }

    setupSearch() {
        const input = document.getElementById('searchInput');
        input.addEventListener('input', () => {
            this.applySearch();
        });
    }

    applySearch() {
        const search = document.getElementById('searchInput').value.toLowerCase();
        const rows = document.querySelectorAll('#hostsTable tr');
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(search) ? '' : 'none';
        });
    }

    updateLastUpdate() {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('ru-RU');
        document.getElementById('lastUpdate').textContent = `Последнее обновление: ${timeStr}`;
    }

    formatTime(date) {
        const now = new Date();
        const diff = now - date;
        const minutes = Math.floor(diff / 60000);
        
        if (minutes < 1) return 'Только что';
        if (minutes < 60) return `${minutes} мин назад`;
        
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours} ч назад`;
        
        return date.toLocaleDateString('ru-RU');
    }

    showMessage(text, type = 'info') {
        const colors = {
            success: '#27ae60',
            error: '#e74c3c',
            warning: '#f39c12',
            info: '#3498db'
        };
        
        // Удаляем старое сообщение
        const oldMsg = document.querySelector('.notification');
        if (oldMsg) oldMsg.remove();
        
        // Создаем новое
        const msg = document.createElement('div');
        msg.className = 'notification';
        msg.innerHTML = text;
        msg.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            background: ${colors[type]};
            color: white;
            border-radius: 5px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            z-index: 1000;
            animation: slideIn 0.3s;
        `;
        
        document.body.appendChild(msg);
        
        // Анимация
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(style);
        
        setTimeout(() => {
            msg.style.animation = 'slideOut 0.3s';
            setTimeout(() => msg.remove(), 300);
        }, 3000);
    }

    showError(text) {
        this.showMessage(text, 'error');
    }
}

// Инициализация
window.scanner = new NetworkScanner();

// Глобальные функции
function scanNetwork() { scanner.scanNetwork(); }
function exportCSV() { scanner.exportCSV(); }
function refreshData() { scanner.refreshData(); }'''
    
    with open('static/js/app.js', 'w', encoding='utf-8') as f:
        f.write(js_content)

def main():
    """Главная функция для Windows"""
    print("""
    ╔═══════════════════════════════════════╗
    ║   Network Scanner Pro для Windows     ║
    ║         Версия 2.0                    ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Проверка прав администратора (рекомендуется)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("⚠  Рекомендуется запускать от имени администратора!")
            print("   Это нужно для полного доступа к сети.")
            response = input("Продолжить? (y/N): ").lower()
            if response != 'y':
                return
    except:
        pass
    
    # Создание необходимых файлов
    if not os.path.exists('templates/index.html'):
        print("📁 Создание файлов интерфейса...")
        create_windows_templates()
    
    # Загрузка конфигурации
    config = Config()
    
    # Инициализация БД
    db_path = config.get('database.path', 'data/network.db')
    database = Database(db_path)
    
    # Инициализация сканера
    scanner = WindowsNetworkScanner(config, database)
    
    # Запуск веб-интерфейса
    web = WebInterface(scanner, config, database)
    
    # Первоначальное сканирование
    if config.get('scanner.auto_scan', True):
        print("🔍 Запуск первоначального сканирования...")
        scan_thread = threading.Thread(target=scanner.scan_network)
        scan_thread.daemon = True
        scan_thread.start()
    
    web.run()

if __name__ == "__main__":
    main()