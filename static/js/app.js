// Network Scanner для Windows - Frontend

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
function refreshData() { scanner.refreshData(); }
// Функции для работы со свободными IP

function showFreeIPs() {
    document.getElementById('freeIpsModal').style.display = 'flex';
    loadFreeIPs();
}

function closeFreeIpsModal() {
    document.getElementById('freeIpsModal').style.display = 'none';
}

async function loadFreeIPs() {
    const network = document.getElementById('networkRange').value;
    const listElement = document.getElementById('freeIpsList');
    const statsElement = document.getElementById('freeIpsStats');
    
    listElement.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Поиск свободных IP...</div>';
    
    try {
        const response = await fetch(`/api/free-ips?network=${encodeURIComponent(network)}`);
        const data = await response.json();
        
        if (data.status === 'success') {
            // Обновляем статистику
            document.getElementById('totalIPs').textContent = data.total_ips;
            document.getElementById('usedIPs').textContent = data.used_ips;
            document.getElementById('freeIPsCount').textContent = data.free_ips_count;
            const percentFree = ((data.free_ips_count / data.total_ips) * 100).toFixed(1);
            document.getElementById('freeIPsPercent').textContent = percentFree + '%';
            statsElement.style.display = 'flex';
            
            // Отображаем список IP
            if (data.free_ips && data.free_ips.length > 0) {
                let html = '';
                data.free_ips.forEach((ip, index) => {
                    // Группируем по последнему октету для удобства
                    if (index > 0 && index % 8 === 0) {
                        html += '<div class="ip-row-break"></div>';
                    }
                    html += `
                        <div class="ip-item" title="Свободный IP: ${ip}">
                            ${ip}
                        </div>
                    `;
                });
                listElement.innerHTML = html;
            } else {
                listElement.innerHTML = '<div class="no-data">Свободные IP не найдены</div>';
            }
        } else {
            listElement.innerHTML = `<div class="error">Ошибка: ${data.message}</div>`;
        }
    } catch (error) {
        console.error('Error loading free IPs:', error);
        listElement.innerHTML = '<div class="error">Ошибка загрузки данных</div>';
    }
}

async function exportFreeIPsCSV() {
    const network = document.getElementById('networkRange').value;
    try {
        const response = await fetch(`/api/free-ips?network=${encodeURIComponent(network)}`);
        const data = await response.json();
        
        if (data.status === 'success' && data.free_ips.length > 0) {
            let csvContent = 'data:text/csv;charset=utf-8,';
            csvContent += 'IP Address,Status,Network,Timestamp\n';
            
            data.free_ips.forEach(ip => {
                csvContent += `${ip},free,${network},${new Date().toISOString()}\n`;
            });
            
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement('a');
            link.setAttribute('href', encodedUri);
            link.setAttribute('download', `free_ips_${network.replace('/', '_')}_${new Date().toISOString().split('T')[0]}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            showNotification(`Экспортировано ${data.free_ips.length} IP`, 'success');
        } else {
            showNotification('Нет данных для экспорта', 'warning');
        }
    } catch (error) {
        console.error('Export error:', error);
        showNotification('Ошибка экспорта', 'error');
    }
}

// Обновляем функцию showNotification, если её нет
function showNotification(message, type = 'info') {
    // ... существующий код уведомлений ...
}