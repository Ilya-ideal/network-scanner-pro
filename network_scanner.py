#!/usr/bin/env python3
"""
Network Scanner Pro для Linux (Debian 12)
Версия: 3.0 Linux Edition
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
import socket
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
import requests

# Настройка логирования для Linux
log_dir = '/var/log/network-scanner'
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

class LinuxNetworkScanner:
    """Сканер сети для Linux"""
    
    def __init__(self, config, database):
        self.config = config
        self.db = database
        self.nm = nmap.PortScanner()
        self.is_scanning = False
        self.network_interfaces = self._get_network_interfaces()
        
    def _get_network_interfaces(self) -> List[Dict]:
        """Получить список сетевых интерфейсов"""
        interfaces = []
        try:
            for iface in netifaces.interfaces():
                if iface == 'lo':
                    continue
                
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get('addr', '')
                        netmask = addr_info.get('netmask', '')
                        if ip and netmask and not ip.startswith('127.'):
                            # Конвертируем в CIDR
                            network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                            interfaces.append({
                                'name': iface,
                                'ip': ip,
                                'netmask': netmask,
                                'cidr': str(network),
                                'mac': addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'Unknown') if netifaces.AF_LINK in addrs else 'Unknown'
                            })
            return interfaces
        except Exception as e:
            logger.error(f"Ошибка получения интерфейсов: {e}")
            return [{'name': 'eth0', 'cidr': '10.0.9.0/24'}]
    
    def get_default_network(self) -> str:
        """Получить сеть по умолчанию"""
        if self.network_interfaces:
            return self.network_interfaces[0]['cidr']
        return self.config.get('network.cidr', '10.0.9.0/24')
    
    def scan_network(self, network_cidr: str = None) -> Dict:
        """Сканирование сети для Linux"""
        if self.is_scanning:
            return {'status': 'error', 'message': 'Сканирование уже выполняется'}
        
        self.is_scanning = True
        start_time = time.time()
        
        try:
            network = network_cidr or self.get_default_network()
            logger.info(f"Сканирование сети: {network}")
            
            # Метод 1: ARP кэш Linux
            arp_hosts = self._scan_linux_arp()
            
            # Метод 2: Ping sweep для Linux
            ping_hosts = self._ping_sweep_linux(network)
            
            # Метод 3: Nmap сканирование
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
                'network': network,
                'interfaces': len(self.network_interfaces)
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Ошибка сканирования: {e}")
            return {'status': 'error', 'message': str(e)}
        finally:
            self.is_scanning = False
    
    def _scan_linux_arp(self) -> List[Dict]:
        """Чтение ARP кэша Linux"""
        hosts = []
        try:
            # Команда arp -n в Linux
            result = subprocess.run(
                ['arp', '-n'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=10
            )
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and 'Address' not in line and 'HWtype' not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        mac = parts[2]
                        if mac != '00:00:00:00:00:00' and ip not in ['224.0.0.0', '255.255.255.255']:
                            hosts.append({
                                'ip': ip,
                                'mac': mac,
                                'status': 'up',
                                'source': 'linux-arp'
                            })
                            
        except Exception as e:
            logger.warning(f"Ошибка чтения ARP кэша: {e}")
        
        return hosts
    
    def _ping_sweep_linux(self, network: str) -> List[Dict]:
        """Ping sweep для Linux"""
        hosts = []
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            
            # Используем fping если установлен (быстрее)
            try:
                # Проверяем наличие fping
                subprocess.run(['which', 'fping'], capture_output=True, check=True)
                use_fping = True
            except:
                use_fping = False
            
            if use_fping:
                # Сканирование с помощью fping
                ip_list = ' '.join(str(network_obj.network_address + i) for i in range(1, 255))
                result = subprocess.run(
                    f'fping -a -g {network} 2>/dev/null',
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                for ip in result.stdout.split('\n'):
                    ip = ip.strip()
                    if ip:
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except:
                            hostname = ""
                        
                        hosts.append({
                            'ip': ip,
                            'status': 'up',
                            'hostname': hostname,
                            'source': 'linux-fping'
                        })
            else:
                # Сканирование обычным ping
                for i in range(1, 255):
                    ip = str(network_obj.network_address + i)
                    
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', ip],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    
                    status = 'up' if result.returncode == 0 else 'down'
                    
                    if status == 'up':
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except:
                            hostname = ""
                        
                        hosts.append({
                            'ip': ip,
                            'status': status,
                            'hostname': hostname,
                            'source': 'linux-ping'
                        })
                    
        except Exception as e:
            logger.warning(f"Ошибка ping sweep: {e}")
        
        return hosts
    
    def _nmap_scan(self, network: str) -> List[Dict]:
        """Сканирование через Nmap"""
        hosts = []
        try:
            # Быстрое сканирование без портов
            self.nm.scan(hosts=network, arguments='-sn -T4 --max-retries 1')
            
            for host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'status': self.nm[host].state(),
                    'source': 'nmap'
                }
                
                if 'addresses' in self.nm[host] and 'mac' in self.nm[host]['addresses']:
                    host_info['mac'] = self.nm[host]['addresses']['mac']
                    
                    if 'vendor' in self.nm[host] and self.nm[host]['addresses']['mac'] in self.nm[host]['vendor']:
                        host_info['vendor'] = self.nm[host]['vendor'][self.nm[host]['addresses']['mac']]
                
                if 'hostnames' in self.nm[host] and self.nm[host]['hostnames']:
                    host_info['hostname'] = self.nm[host]['hostnames'][0]['name']
                
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
                    for key, value in host.items():
                        if value and (key not in merged[ip] or not merged[ip][key]):
                            merged[ip][key] = value
                else:
                    merged[ip] = host
        return list(merged.values())
    
    def ping_host(self, ip: str) -> Dict:
        """Пинг отдельного хоста для Linux"""
        try:
            result = subprocess.run(
                ['ping', '-c', '2', '-W', '2', ip],
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
    
    def get_network_info(self) -> Dict:
        """Получить информацию о сети"""
        return {
            'interfaces': self.network_interfaces,
            'default_network': self.get_default_network(),
            'hostname': socket.gethostname(),
            'system': platform.system(),
            'release': platform.release()
        }

class Config:
    def __init__(self, config_file='/etc/network-scanner/config.json'):
        self.config_file = config_file
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        self.config = self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Ошибка загрузки конфигурации: {e}")
        
        # Конфигурация по умолчанию для Linux
        default_config = {
            'network': {'auto_detect': True, 'scan_interface': 'eth0'},
            'server': {'host': '0.0.0.0', 'port': 8000, 'debug': False},
            'scanner': {'scan_interval': 300, 'auto_scan': True, 'max_hosts': 254},
            'database': {'path': '/var/lib/network-scanner/network.db'},
            'security': {'auth_required': False, 'allowed_networks': ['10.0.9.0/24']}
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
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
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
                    host_group TEXT DEFAULT 'default',
                    scan_count INTEGER DEFAULT 0
                )
            ''')
            
            # Индексы для быстрого поиска
            c.execute('CREATE INDEX IF NOT EXISTS idx_ip ON hosts(ip)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_status ON hosts(status)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_mac ON hosts(mac)')
            
            conn.commit()
    
    def save_host(self, host):
        try:
            with self.get_connection() as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT id, scan_count FROM hosts WHERE ip = ?
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
                            last_response = ?,
                            scan_count = scan_count + 1
                        WHERE ip = ?
                    ''', (host.mac, host.hostname, host.vendor, 
                          host.status, host.last_seen, 
                          host.last_response, host.ip))
                else:
                    c.execute('''
                        INSERT INTO hosts (ip, mac, hostname, vendor, status, 
                                          first_seen, last_seen, last_response, scan_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
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
                c.execute("SELECT COUNT(DISTINCT vendor) as vendors FROM hosts WHERE vendor != 'Unknown'")
                vendors = c.fetchone()[0]
                c.execute("SELECT MAX(scan_count) as max_scans FROM hosts")
                max_scans = c.fetchone()[0]
                
                return {
                    'total_hosts': total,
                    'online_hosts': online,
                    'offline_hosts': offline,
                    'unique_vendors': vendors,
                    'max_scan_count': max_scans or 0,
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
        self.app.config['SECRET_KEY'] = 'network-scanner-secret-key-2024'
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
        
        @self.app.route('/api/network/info', methods=['GET'])
        def get_network_info():
            try:
                info = self.scanner.get_network_info()
                return jsonify({'status': 'success', 'info': info})
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            try:
                data = request.get_json() or {}
                network = data.get('network')
                
                def scan_task():
                    result = self.scanner.scan_network(network)
                    logger.info(f"Сканирование завершено: {result}")
                
                thread = threading.Thread(target=scan_task)
                thread.daemon = True
                thread.start()
                
                return jsonify({
                    'status': 'success',
                    'message': 'Сканирование запущено в фоновом режиме'
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
                    'first_seen', 'last_seen', 'last_response', 'scan_count'
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
                        'last_seen': host['last_seen'],
                        'last_response': host['last_response'] or '',
                        'scan_count': host.get('scan_count', 0)
                    })
                
                response = Response(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=network_hosts.csv'}
                )
                return response
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/free-ips', methods=['GET'])
        def get_free_ips():
            try:
                network_cidr = request.args.get('network', self.scanner.get_default_network())
                
                all_hosts = self.db.get_all_hosts()
                used_ips = {host['ip'] for host in all_hosts}
                
                network = ipaddress.ip_network(network_cidr, strict=False)
                all_ips = [str(ip) for ip in network.hosts()]
                
                free_ips = [ip for ip in all_ips if ip not in used_ips]
                
                return jsonify({
                    'status': 'success',
                    'network': network_cidr,
                    'total_ips': len(all_ips),
                    'used_ips': len(used_ips),
                    'free_ips_count': len(free_ips),
                    'free_ips': free_ips[:100],
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Ошибка получения свободных IP: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/interfaces', methods=['GET'])
        def get_interfaces():
            try:
                interfaces = self.scanner.network_interfaces
                return jsonify({
                    'status': 'success',
                    'interfaces': interfaces
                })
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/static/<path:filename>')
        def static_files(filename):
            try:
                return send_file(f'static/{filename}')
            except:
                return jsonify({'status': 'error', 'message': 'File not found'}), 404

    def run(self):
        host = self.config.get('server.host', '0.0.0.0')
        port = self.config.get('server.port', 8000)
        debug = self.config.get('server.debug', False)
        
        print(f"\n{'='*60}")
        print("   Network Scanner Pro для Linux")
        print("   Версия: 3.0 (Debian 12)")
        print(f"{'='*60}")
        print(f"🌐 Веб-интерфейс: http://{host}:{port}")
        print(f"🔧 API хостов: http://{host}:{port}/api/hosts")
        print(f"📊 Статистика: http://{host}:{port}/api/stats")
        print(f"📡 Сеть: http://{host}:{port}/api/network/info")
        print(f"{'='*60}")
        print(f"📁 Логи: /var/log/network-scanner/scanner.log")
        print(f"💾 База данных: {self.config.get('database.path')}")
        print(f"{'='*60}\n")
        
        self.app.run(host=host, port=port, debug=debug, threaded=True)

def create_linux_templates():
    """Создание HTML/CSS/JS файлов для Linux"""
    
    # Создаем директории
    base_dir = '/opt/network-scanner'
    os.makedirs(os.path.join(base_dir, 'templates'), exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'static/css'), exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'static/js'), exist_ok=True)
    
    # HTML файл
    html_content = '''<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scanner - Linux</title>
    <link rel="stylesheet" href="/static/css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.min.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="header-top">
                <h1><i class="fas fa-network-wired"></i> Network Scanner для Linux</h1>
                <div class="system-info">
                    <span id="systemHostname"></span>
                    <span id="currentNetwork"></span>
                </div>
            </div>
            <div class="header-bottom">
                <span id="lastUpdate">Последнее обновление: --:--:--</span>
                <span id="scannerStatus">Статус: <span class="status-idle">Ожидание</span></span>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="stats-grid">
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
                    <i class="fas fa-microchip"></i>
                    <div>
                        <h3>Производителей</h3>
                        <p id="vendorsCount">0</p>
                    </div>
                </div>
            </div>
            
            <div class="controls">
                <button onclick="scanner.scanNetwork()" class="btn btn-primary">
                    <i class="fas fa-search"></i> Сканировать сеть
                </button>
                <button onclick="scanner.exportCSV()" class="btn btn-secondary">
                    <i class="fas fa-download"></i> Экспорт CSV
                </button>
                <button onclick="scanner.refreshData()" class="btn">
                    <i class="fas fa-redo"></i> Обновить
                </button>
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="Поиск по IP, имени или MAC...">
                    <i class="fas fa-search"></i>
                </div>
                <select id="networkSelect" class="network-select">
                    <option value="">Выберите сеть...</option>
                </select>
            </div>
        </div>
        
        <div class="content">
            <div class="table-container">
                <div class="table-header">
                    <h2><i class="fas fa-list"></i> Обнаруженные устройства</h2>
                    <div class="table-actions">
                        <button onclick="scanner.showFreeIPs()" class="btn btn-small">
                            <i class="fas fa-list-ol"></i> Свободные IP
                        </button>
                        <button onclick="scanner.showInterfaces()" class="btn btn-small">
                            <i class="fas fa-ethernet"></i> Интерфейсы
                        </button>
                    </div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>IP Адрес</th>
                            <th>Имя хоста</th>
                            <th>MAC Адрес</th>
                            <th>Производитель</th>
                            <th>Статус</th>
                            <th>Первое обнаружение</th>
                            <th>Последний ответ</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody id="hostsTable">
                        <tr>
                            <td colspan="8" class="loading">
                                <i class="fas fa-spinner fa-spin"></i> Загрузка данных...
                            </td>
                        </tr>
                    </tbody>
                </table>
                <div class="table-footer">
                    <div id="tableInfo">Загружено 0 устройств</div>
                    <div class="pagination">
                        <button onclick="scanner.prevPage()" disabled id="prevBtn">
                            <i class="fas fa-chevron-left"></i>
                        </button>
                        <span id="pageInfo">Страница 1</span>
                        <button onclick="scanner.nextPage()" disabled id="nextBtn">
                            <i class="fas fa-chevron-right"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <footer>
            <p>Network Scanner Pro для Linux | Автообновление каждые 60 секунд | Debian 12</p>
        </footer>
    </div>
    
    <!-- Модальные окна -->
    <div id="freeIPsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-list-ol"></i> Свободные IP адреса</h3>
                <span class="close" onclick="scanner.closeModal('freeIPsModal')">&times;</span>
            </div>
            <div class="modal-body">
                <div id="freeIPsContent"></div>
            </div>
        </div>
    </div>
    
    <div id="interfacesModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-ethernet"></i> Сетевые интерфейсы</h3>
                <span class="close" onclick="scanner.closeModal('interfacesModal')">&times;</span>
            </div>
            <div class="modal-body">
                <div id="interfacesContent"></div>
            </div>
        </div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.min.js"></script>
    <script src="/static/js/app.js"></script>
</body>
</html>'''
    
    with open(os.path.join(base_dir, 'templates/index.html'), 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # CSS файл
    css_content = '''* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Ubuntu', sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
    color: #333;
}

.container {
    max-width: 1800px;
    margin: 0 auto;
    background: white;
    border-radius: 12px;
    box-shadow: 0 15px 35px rgba(0,0,0,0.2);
    overflow: hidden;
    display: flex;
    flex-direction: column;
    min-height: calc(100vh - 40px);
}

/* Header */
header {
    background: linear-gradient(135deg, #2c3e50 0%, #4a6491 100%);
    color: white;
    padding: 20px 30px;
}

.header-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    flex-wrap: wrap;
    gap: 20px;
}

.header-top h1 {
    font-size: 28px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-weight: 500;
}

.system-info {
    display: flex;
    gap: 25px;
    font-size: 14px;
    background: rgba(255,255,255,0.1);
    padding: 8px 15px;
    border-radius: 6px;
}

.header-bottom {
    display: flex;
    justify-content: space-between;
    font-size: 14px;
    opacity: 0.9;
    padding-top: 10px;
    border-top: 1px solid rgba(255,255,255,0.1);
}

.status-idle {
    color: #f39c12;
    font-weight: bold;
}
.status-scanning {
    color: #3498db;
    font-weight: bold;
}

/* Dashboard */
.dashboard {
    padding: 25px 30px;
    background: #f8f9fa;
    border-bottom: 1px solid #e9ecef;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 20px;
    margin-bottom: 25px;
}

.stat-card {
    background: white;
    padding: 22px;
    border-radius: 10px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    display: flex;
    align-items: center;
    gap: 18px;
    transition: all 0.3s ease;
    border-left: 4px solid #3498db;
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 8px 20px rgba(0,0,0,0.12);
}

.stat-card i {
    font-size: 36px;
    color: #3498db;
}

.stat-card h3 {
    font-size: 14px;
    color: #6c757d;
    margin-bottom: 6px;
    font-weight: 500;
}

.stat-card p {
    font-size: 32px;
    font-weight: 700;
    color: #2c3e50;
}

/* Controls */
.controls {
    display: flex;
    gap: 15px;
    align-items: center;
    flex-wrap: wrap;
}

.btn {
    padding: 12px 24px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-weight: 500;
    font-size: 15px;
    transition: all 0.2s;
    text-decoration: none;
    white-space: nowrap;
}

.btn-primary {
    background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
    color: white;
}

.btn-primary:hover {
    background: linear-gradient(135deg, #2980b9 0%, #1f6394 100%);
    transform: translateY(-2px);
}

.btn-secondary {
    background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%);
    color: white;
}

.btn-secondary:hover {
    background: linear-gradient(135deg, #7f8c8d 0%, #6c7b7d 100%);
    transform: translateY(-2px);
}

.btn-small {
    padding: 8px 16px;
    font-size: 14px;
}

.search-box {
    flex: 1;
    max-width: 300px;
    position: relative;
}

.search-box input {
    width: 100%;
    padding: 12px 15px 12px 42px;
    border: 2px solid #dee2e6;
    border-radius: 6px;
    font-size: 15px;
    transition: border-color 0.2s;
}

.search-box input:focus {
    outline: none;
    border-color: #3498db;
}

.search-box i {
    position: absolute;
    left: 15px;
    top: 50%;
    transform: translateY(-50%);
    color: #6c757d;
}

.network-select {
    padding: 11px 15px;
    border: 2px solid #dee2e6;
    border-radius: 6px;
    background: white;
    font-size: 15px;
    min-width: 200px;
}

/* Content */
.content {
    flex: 1;
    padding: 30px;
}

.table-container {
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    overflow: hidden;
}

.table-header {
    padding: 20px 25px;
    border-bottom: 1px solid #e9ecef;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.table-header h2 {
    font-size: 20px;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 10px;
}

.table-actions {
    display: flex;
    gap: 10px;
}

/* Table */
table {
    width: 100%;
    border-collapse: collapse;
}

thead {
    background: #f8f9fa;
}

th {
    padding: 16px 20px;
    text-align: left;
    font-weight: 600;
    color: #495057;
    border-bottom: 2px solid #dee2e6;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

td {
    padding: 16px 20px;
    border-bottom: 1px solid #e9ecef;
    font-size: 14px;
}

tr:hover {
    background: #f8f9fa;
}

.status {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.3px;
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
    padding: 6px 12px;
    border: 1px solid #dee2e6;
    background: white;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.2s;
    font-size: 12px;
}

.action-btn:hover {
    background: #f8f9fa;
    border-color: #3498db;
    color: #3498db;
}

.loading {
    text-align: center;
    padding: 60px 20px;
    color: #6c757d;
    font-size: 16px;
}

.loading i {
    margin-right: 10px;
}

.table-footer {
    padding: 20px 25px;
    border-top: 1px solid #e9ecef;
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #f8f9fa;
}

.pagination {
    display: flex;
    align-items: center;
    gap: 15px;
}

.pagination button {
    padding: 8px 15px;
    border: 1px solid #dee2e6;
    background: white;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.2s;
}

.pagination button:hover:not(:disabled) {
    background: #f8f9fa;
    border-color: #3498db;
}

.pagination button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

/* Footer */
footer {
    padding: 20px 30px;
    text-align: center;
    color: #6c757d;
    font-size: 14px;
    background: #f8f9fa;
    border-top: 1px solid #e9ecef;
}

/* Modal */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.5);
}

.modal-content {
    background: white;
    margin: 5% auto;
    padding: 0;
    border-radius: 10px;
    width: 90%;
    max-width: 800px;
    max-height: 80vh;
    overflow: hidden;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
}

.modal-header {
    padding: 20px 25px;
    background: #2c3e50;
    color: white;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.modal-header h3 {
    font-size: 20px;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 10px;
}

.close {
    font-size: 28px;
    cursor: pointer;
    opacity: 0.8;
    transition: opacity 0.2s;
}

.close:hover {
    opacity: 1;
}

.modal-body {
    padding: 25px;
    max-height: calc(80vh - 73px);
    overflow-y: auto;
}

/* Toastr customization */
.toast-success {
    background: #27ae60 !important;
}
.toast-error {
    background: #e74c3c !important;
}
.toast-info {
    background: #3498db !important;
}
.toast-warning {
    background: #f39c12 !important;
}

/* Responsive */
@media (max-width: 1200px) {
    .container {
        margin: 10px;
        width: calc(100% - 20px);
    }
}

@media (max-width: 992px) {
    .header-top {
        flex-direction: column;
        text-align: center;
    }
    
    .controls {
        flex-direction: column;
        align-items: stretch;
    }
    
    .search-box, .network-select {
        max-width: 100%;
        width: 100%;
    }
    
    .table-header {
        flex-direction: column;
        gap: 15px;
        text-align: center;
    }
    
    .table-footer {
        flex-direction: column;
        gap: 15px;
    }
}

@media (max-width: 768px) {
    th, td {
        padding: 12px 15px;
    }
    
    .stat-card {
        flex-direction: column;
        text-align: center;
        padding: 20px;
    }
    
    .actions {
        flex-direction: column;
    }
    
    .modal-content {
        width: 95%;
        margin: 10% auto;
    }
}

@media (max-width: 576px) {
    body {
        padding: 10px;
    }
    
    .container {
        border-radius: 8px;
    }
    
    header, .dashboard, .content {
        padding: 20px;
    }
    
    .header-bottom {
        flex-direction: column;
        gap: 10px;
        text-align: center;
    }
}'''
    
    with open(os.path.join(base_dir, 'static/css/style.css'), 'w', encoding='utf-8') as f:
        f.write(css_content)
    
    # JavaScript файл
    js_content = '''// Network Scanner для Linux - Frontend

class NetworkScanner {
    constructor() {
        this.apiBase = '/api';
        this.currentPage = 1;
        this.pageSize = 50;
        this.allHosts = [];
        this.currentNetwork = '';
        this.init();
    }

    init() {
        toastr.options = {
            "closeButton": true,
            "progressBar": true,
            "positionClass": "toast-top-right",
            "timeOut": "3000"
        };
        
        this.loadSystemInfo();
        this.loadNetworkInterfaces();
        this.loadData();
        this.setupAutoRefresh();
        this.setupSearch();
        this.setupEventListeners();
    }

    async loadSystemInfo() {
        try {
            const response = await fetch(`${this.apiBase}/network/info`);
            const data = await response.json();
            
            if (data.status === 'success') {
                const info = data.info;
                document.getElementById('systemHostname').innerHTML = 
                    `<i class="fas fa-desktop"></i> ${info.hostname}`;
                document.getElementById('currentNetwork').innerHTML = 
                    `<i class="fas fa-network-wired"></i> ${info.default_network}`;
                this.currentNetwork = info.default_network;
            }
        } catch (error) {
            console.error('Error loading system info:', error);
        }
    }

    async loadNetworkInterfaces() {
        try {
            const response = await fetch(`${this.apiBase}/interfaces`);
            const data = await response.json();
            
            if (data.status === 'success') {
                const select = document.getElementById('networkSelect');
                select.innerHTML = '<option value="">Выберите сеть...</option>';
                
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.cidr;
                    option.textContent = `${iface.name} - ${iface.cidr} (${iface.ip})`;
                    select.appendChild(option);
                });
                
                // Выбираем текущую сеть
                if (this.currentNetwork) {
                    select.value = this.currentNetwork;
                }
            }
        } catch (error) {
            console.error('Error loading interfaces:', error);
        }
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
            this.setScannerStatus('Загрузка...', 'scanning');
            
            const response = await fetch(`${this.apiBase}/hosts`);
            const data = await response.json();
            
            if (data.status === 'success') {
                this.allHosts = data.hosts;
                this.renderPage(1);
                document.getElementById('tableInfo').textContent = 
                    `Загружено ${this.allHosts.length} устройств`;
            } else {
                this.showError('Не удалось загрузить список устройств');
            }
        } catch (error) {
            console.error('Error loading hosts:', error);
            this.showError('Ошибка соединения с сервером');
        } finally {
            this.setScannerStatus('Ожидание', 'idle');
        }
    }

    renderPage(page) {
        this.currentPage = page;
        const start = (page - 1) * this.pageSize;
        const end = start + this.pageSize;
        const pageHosts = this.allHosts.slice(start, end);
        
        this.renderHosts(pageHosts);
        this.updatePagination();
    }

    renderHosts(hosts) {
        const table = document.getElementById('hostsTable');
        
        if (hosts.length === 0) {
            table.innerHTML = `
                <tr>
                    <td colspan="8" class="loading">
                        <i class="fas fa-inbox"></i>
                        <p>Устройства не найдены. Запустите сканирование.</p>
                    </td>
                </tr>
            `;
            return;
        }

        let html = '';
        hosts.forEach(host => {
            const statusClass = host.status === 'up' ? 'online' : 'offline';
            const statusText = host.status === 'up' ? 'ОНЛАЙН' : 'ОФФЛАЙН';
            
            const firstSeen = host.first_seen ? 
                this.formatDateTime(new Date(host.first_seen)) : 'Неизвестно';
            
            const lastResponse = host.last_response ? 
                this.formatDateTime(new Date(host.last_response)) : 'Никогда';

            html += `
                <tr>
                    <td><strong>${host.ip}</strong></td>
                    <td>${host.hostname || host.custom_name || '-'}</td>
                    <td><code class="mac-address">${host.mac || 'Неизвестно'}</code></td>
                    <td>${host.vendor || 'Неизвестно'}</td>
                    <td>
                        <span class="status ${statusClass}">
                            ${statusText}
                        </span>
                    </td>
                    <td>${firstSeen}</td>
                    <td>${lastResponse}</td>
                    <td>
                        <div class="actions">
                            <button class="action-btn" onclick="scanner.ping('${host.ip}')" title="Пинг">
                                <i class="fas fa-signal"></i> Пинг
                            </button>
                            <button class="action-btn" onclick="scanner.editHost('${host.ip}')" title="Редактировать">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="action-btn" onclick="scanner.viewDetails('${host.ip}')" title="Подробности">
                                <i class="fas fa-info-circle"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });

        table.innerHTML = html;
        this.applySearch();
    }

    updatePagination() {
        const totalPages = Math.ceil(this.allHosts.length / this.pageSize);
        document.getElementById('pageInfo').textContent = `Страница ${this.currentPage} из ${totalPages}`;
        
        document.getElementById('prevBtn').disabled = this.currentPage <= 1;
        document.getElementById('nextBtn').disabled = this.currentPage >= totalPages;
    }

    nextPage() {
        const totalPages = Math.ceil(this.allHosts.length / this.pageSize);
        if (this.currentPage < totalPages) {
            this.renderPage(this.currentPage + 1);
        }
    }

    prevPage() {
        if (this.currentPage > 1) {
            this.renderPage(this.currentPage - 1);
        }
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
                document.getElementById('vendorsCount').textContent = stats.unique_vendors || 0;
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    async scanNetwork() {
        const networkSelect = document.getElementById('networkSelect');
        const network = networkSelect.value || this.currentNetwork;
        
        if (!network) {
            this.showWarning('Выберите сеть для сканирования');
            return;
        }
        
        this.setScannerStatus('Сканирование...', 'scanning');
        
        try {
            const response = await fetch(`${this.apiBase}/scan`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({network: network})
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showSuccess('Сканирование запущено. Данные обновятся через 10 секунд.');
                
                setTimeout(() => {
                    this.loadData();
                    this.showInfo('Сканирование завершено');
                }, 10000);
            } else {
                this.showError(data.message || 'Ошибка сканирования');
                this.setScannerStatus('Ошибка', 'idle');
            }
        } catch (error) {
            this.showError('Не удалось запустить сканирование');
            console.error('Error:', error);
            this.setScannerStatus('Ошибка', 'idle');
        }
    }

    async ping(ip) {
        try {
            const response = await fetch(`${this.apiBase}/ping/${ip}`);
            const data = await response.json();
            
            if (data.status === 'success') {
                if (data.online) {
                    this.showSuccess(`Хост ${ip} доступен`);
                } else {
                    this.showWarning(`Хост ${ip} недоступен`);
                }
                setTimeout(() => this.loadHosts(), 1000);
            } else {
                this.showError(data.message || 'Ошибка пинга');
            }
        } catch (error) {
            this.showError(`Ошибка пинга ${ip}`);
        }
    }

    editHost(ip) {
        const newName = prompt(`Введите новое имя для ${ip}:`, '');
        if (newName !== null && newName.trim()) {
            this.updateHost(ip, {custom_name: newName.trim()});
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
                this.showSuccess('Информация обновлена');
                this.loadHosts();
            } else {
                this.showError(result.message || 'Ошибка обновления');
            }
        } catch (error) {
            this.showError('Ошибка обновления');
        }
    }

    viewDetails(ip) {
        const host = this.allHosts.find(h => h.ip === ip);
        if (host) {
            const details = `
                <h4>Подробности устройства</h4>
                <table class="details-table">
                    <tr><td><strong>IP:</strong></td><td>${host.ip}</td></tr>
                    <tr><td><strong>MAC:</strong></td><td>${host.mac || 'Неизвестно'}</td></tr>
                    <tr><td><strong>Имя:</strong></td><td>${host.hostname || 'Неизвестно'}</td></tr>
                    <tr><td><strong>Производитель:</strong></td><td>${host.vendor || 'Неизвестно'}</td></tr>
                    <tr><td><strong>Статус:</strong></td><td>${host.status}</td></tr>
                    <tr><td><strong>Первый раз видели:</strong></td><td>${this.formatDateTime(new Date(host.first_seen))}</td></tr>
                    <tr><td><strong>Последний ответ:</strong></td><td>${this.formatDateTime(new Date(host.last_response))}</td></tr>
                    <tr><td><strong>Сканирований:</strong></td><td>${host.scan_count || 0}</td></tr>
                </table>
            `;
            this.showModal('Детали устройства', details);
        }
    }

    async exportCSV() {
        try {
            const response = await fetch(`${this.apiBase}/export/csv`);
            const blob = await response.blob();
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `network_scan_${new Date().toISOString().slice(0,10)}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            this.showSuccess('Экспорт завершен');
        } catch (error) {
            this.showError('Ошибка экспорта');
        }
    }

    async showFreeIPs() {
        try {
            const network = document.getElementById('networkSelect').value || this.currentNetwork;
            if (!network) {
                this.showWarning('Выберите сеть');
                return;
            }
            
            const response = await fetch(`${this.apiBase}/free-ips?network=${encodeURIComponent(network)}`);
            const data = await response.json();
            
            if (data.status === 'success') {
                let content = `
                    <p><strong>Сеть:</strong> ${data.network}</p>
                    <p><strong>Всего IP:</strong> ${data.total_ips}</p>
                    <p><strong>Занято:</strong> ${data.used_ips}</p>
                    <p><strong>Свободно:</strong> ${data.free_ips_count}</p>
                    <h4>Свободные IP адреса:</h4>
                    <div class="ip-list">
                `;
                
                data.free_ips.forEach(ip => {
                    content += `<span class="ip-item">${ip}</span>`;
                });
                
                content += `</div>`;
                
                document.getElementById('freeIPsContent').innerHTML = content;
                this.showModal('freeIPsModal');
            }
        } catch (error) {
            this.showError('Ошибка загрузки свободных IP');
        }
    }

    async showInterfaces() {
        try {
            const response = await fetch(`${this.apiBase}/interfaces`);
            const data = await response.json();
            
            if (data.status === 'success') {
                let content = '<div class="interfaces-list">';
                
                data.interfaces.forEach(iface => {
                    content += `
                        <div class="interface-card">
                            <h4><i class="fas fa-network-wired"></i> ${iface.name}</h4>
                            <table>
                                <tr><td><strong>IP:</strong></td><td>${iface.ip}</td></tr>
                                <tr><td><strong>Сеть:</strong></td><td>${iface.cidr}</td></tr>
                                <tr><td><strong>Маска:</strong></td><td>${iface.netmask}</td></tr>
                                <tr><td><strong>MAC:</strong></td><td>${iface.mac}</td></tr>
                            </table>
                        </div>
                    `;
                });
                
                content += '</div>';
                
                document.getElementById('interfacesContent').innerHTML = content;
                this.showModal('interfacesModal');
            }
        } catch (error) {
            this.showError('Ошибка загрузки интерфейсов');
        }
    }

    refreshData() {
        this.loadData();
        this.showInfo('Данные обновлены');
    }

    setScannerStatus(text, type) {
        const statusEl = document.querySelector('#scannerStatus span');
        statusEl.textContent = text;
        statusEl.className = `status-${type}`;
        
        if (type === 'scanning') {
            statusEl.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
        }
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

    setupEventListeners() {
        document.getElementById('networkSelect').addEventListener('change', (e) => {
            if (e.target.value) {
                this.currentNetwork = e.target.value;
            }
        });
    }

    applySearch() {
        const search = document.getElementById('searchInput').value.toLowerCase();
        const rows = document.querySelectorAll('#hostsTable tr');
        
        rows.forEach(row => {
            if (row.cells.length > 1) {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(search) ? '' : 'none';
            }
        });
    }

    updateLastUpdate() {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('ru-RU');
        document.getElementById('lastUpdate').textContent = `Последнее обновление: ${timeStr}`;
    }

    formatDateTime(date) {
        if (!date || isNaN(date.getTime())) return 'Неизвестно';
        
        const now = new Date();
        const diff = now - date;
        const minutes = Math.floor(diff / 60000);
        
        if (minutes < 1) return 'Только что';
        if (minutes < 60) return `${minutes} мин назад`;
        
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours} ч назад`;
        
        return date.toLocaleDateString('ru-RU') + ' ' + date.toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'});
    }

    showModal(modalId) {
        document.getElementById(modalId).style.display = 'block';
    }

    closeModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
    }

    // Toast сообщения
    showSuccess(message) {
        toastr.success(message);
    }

    showError(message) {
        toastr.error(message);
    }

    showWarning(message) {
        toastr.warning(message);
    }

    showInfo(message) {
        toastr.info(message);
    }
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    window.scanner = new NetworkScanner();
});

// Глобальные функции
function scanNetwork() { scanner.scanNetwork(); }
function exportCSV() { scanner.exportCSV(); }
function refreshData() { scanner.refreshData(); }'''
    
    with open(os.path.join(base_dir, 'static/js/app.js'), 'w', encoding='utf-8') as f:
        f.write(js_content)

def check_dependencies():
    """Проверка зависимостей для Linux"""
    dependencies = [
        'python3-nmap',
        'nmap',
        'arp-scan',
        'fping',
        'net-tools'
    ]
    
    print("🔍 Проверка зависимостей...")
    
    for dep in dependencies:
        try:
            subprocess.run(['which', dep.split('-')[0]], 
                         capture_output=True, check=True)
            print(f"✅ {dep}")
        except:
            print(f"⚠  {dep} не установлен")
    
    print("\nДля установки зависимостей выполните:")
    print("sudo apt update && sudo apt install python3-pip nmap arp-scan fping net-tools")
    print("sudo pip3 install python-nmap netifaces flask flask-cors apscheduler")

def main():
    """Главная функция для Linux"""
    print("""
    ╔══════════════════════════════════════════════╗
    ║     Network Scanner Pro для Linux           ║
    ║          Версия 3.0 (Debian 12)             ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # Проверка прав
    if os.geteuid() != 0:
        print("⚠  Рекомендуется запускать с правами root для полного доступа к сети.")
        print("   sudo python3 network_scanner.py")
        response = input("Продолжить? (y/N): ").lower()
        if response != 'y':
            return
    
    # Проверка зависимостей
    check_dependencies()
    
    # Создание необходимых директорий
    base_dir = '/opt/network-scanner'
    os.makedirs(base_dir, exist_ok=True)
    os.chdir(base_dir)
    
    # Создание файлов интерфейса
    if not os.path.exists('templates/index.html'):
        print("📁 Создание файлов интерфейса...")
        create_linux_templates()
    
    # Загрузка конфигурации
    config = Config()
    
    # Инициализация БД
    db_path = config.get('database.path', '/var/lib/network-scanner/network.db')
    database = Database(db_path)
    
    # Инициализация сканера
    scanner = LinuxNetworkScanner(config, database)
    
    # Запуск веб-интерфейса
    web = WebInterface(scanner, config, database)
    
    # Планировщик для автоматического сканирования
    if config.get('scanner.auto_scan', True):
        scheduler = BackgroundScheduler()
        scan_interval = config.get('scanner.scan_interval', 300)
        
        def auto_scan():
            if not scanner.is_scanning:
                logger.info("Автоматическое сканирование...")
                scanner.scan_network()
        
        scheduler.add_job(auto_scan, 'interval', seconds=scan_interval)
        scheduler.start()
        print(f"🔄 Автосканирование каждые {scan_interval} секунд")
    
    web.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Завершение работы...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        logger.exception("Критическая ошибка")
        sys.exit(1)