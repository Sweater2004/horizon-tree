// ====== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ======
const API = '';
let token = localStorage.getItem('auth_token');
let currentUser = null;
let currentMap = null;
let network = null;
let selectedNodeId = null;
let selectedNode = null;
let autoRefreshTimer = null;
let autoRefreshEnabled = false;
const AUTO_REFRESH_INTERVAL = 15;
let collapsedNodes = new Set();
let draggedNodeId = null;

// ====== УТИЛИТЫ ======
function showNotification(message, type = 'info') {
    const el = document.createElement('div');
    el.className = `notification ${type}`;
    el.textContent = message;
    document.getElementById('notifications').appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

async function api(path, options = {}) {
    options.headers = options.headers || {};
    options.headers['Authorization'] = `Bearer ${token}`;
    if (options.body && !(options.body instanceof FormData)) {
        options.headers['Content-Type'] = 'application/json';
    }
    const resp = await fetch(API + path, options);
    if (resp.status === 401) {
        localStorage.removeItem('auth_token');
        window.location.href = '/login';
        return null;
    }
    return resp;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ====== ЗАГРУЗКА ПОЛЬЗОВАТЕЛЯ ======
async function loadUser() {
    const resp = await api('/api/auth/me');
    if (!resp) return;
    currentUser = await resp.json();
    document.getElementById('userBadge').textContent = `${currentUser.username} · ${currentUser.role}`;
    if (currentUser.role === 'admin') {
        const adminBtn = document.getElementById('adminBtn');
        if (adminBtn) adminBtn.style.display = 'inline-flex';
    }
}

// ====== ЗАГРУЗКА КАРТ ======
async function loadMaps() {
    const resp = await api('/api/maps');
    if (!resp) return;
    const data = await resp.json();
    const list = document.getElementById('mapsList');
    if (!data.maps || data.maps.length === 0) {
        list.innerHTML = '<div style="color: var(--md-on-surface-muted); font-size: 13px; padding: 8px;">Нет карт</div>';
        return;
    }
    list.innerHTML = data.maps.map(m => `
        <div class="map-item ${currentMap && currentMap.id === m.id ? 'active' : ''}"
             onclick="selectMap('${m.id}')">
            <div class="map-item-name">${escapeHtml(m.name)}</div>
            <div class="map-item-meta">${m.access_level} · v${m.current_version || 1}</div>
        </div>
    `).join('');
}

// ====== ВЫБОР КАРТЫ ======
async function selectMap(mapId) {
    const isSameMap = currentMap && currentMap.id === mapId;
    const resp = await api(`/api/maps/${mapId}`);
    if (!resp) return;
    const newMap = await resp.json();
    currentMap = newMap;

    // Сообщаем серверу, что карта активна
    try {
        await api(`/api/maps/${mapId}/activate`, { method: 'POST' });
    } catch (e) {
        console.debug('activate map error:', e);
    }

    document.getElementById('emptyState').style.display = 
        (currentMap.data.nodes && currentMap.data.nodes.length > 0) ? 'none' : 'block';

    document.getElementById('currentMapBar').style.display = 'flex';
    document.getElementById('currentMapName').textContent = currentMap.name || 'Без имени';
    document.getElementById('currentMapVersion').textContent = 
        `v${currentMap.current_version || 1} · ${currentMap.access_level || 'view'}`;

    if (!isSameMap) {
        selectedNode = null;
        selectedNodeId = null;
        document.getElementById('propsPanel').classList.remove('show');
        initGraph();
    } else {
        updateGraphData();
    }
    renderTree();
    loadMaps();
    loadMapStats();
}

// ====== ДЕРЕВО (с защитой от циклов) ======
function renderTree() {
    const list = document.getElementById('treeList');
    if (!currentMap || !currentMap.data.nodes || currentMap.data.nodes.length === 0) {
        list.innerHTML = '<div style="color: var(--md-on-surface-muted); font-size: 13px; text-align: center; padding: 20px;">Нет узлов</div>';
        return;
    }
    
    const nodes = currentMap.data.nodes;
    const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));
    const byParent = {};
    nodes.forEach(n => {
        let pid = n.parent_id || '__root__';
        if (pid !== '__root__' && !nodeMap[pid]) pid = '__root__';
        if (!byParent[pid]) byParent[pid] = [];
        byParent[pid].push(n);
    });

    const statusOrder = { online: 0, mixed: 1, offline: 2, unknown: 3 };
    Object.keys(byParent).forEach(key => {
        byParent[key].sort((a, b) => (statusOrder[a.aggregated_status] ?? 4) - (statusOrder[b.aggregated_status] ?? 4));
    });

    const visited = new Set();
    function renderNode(node, depth) {
        if (visited.has(node.id)) return '';
        visited.add(node.id);

        const status = node.aggregated_status || 'unknown';
        const isCollapsed = collapsedNodes.has(node.id);
        const hasKids = (byParent[node.id] || []).length > 0;
        const isSelected = selectedNodeId === node.id;
        const toggleIcon = hasKids ? (isCollapsed ? '▶' : '▼') : '';

        return `
            <div class="tree-node ${isSelected ? 'selected' : ''}" 
                 data-node-id="${node.id}" draggable="true"
                 onclick="selectNode('${node.id}')">
                <span class="tree-toggle ${hasKids ? '' : 'empty'}" 
                      onclick="event.stopPropagation(); toggleNodeCollapse('${node.id}')">
                    ${toggleIcon}
                </span>
                <div class="tree-status-dot ${status}"></div>
                <div class="tree-node-content">
                    <div class="tree-node-name">${escapeHtml(node.name || node.ip)}</div>
                    <div class="tree-node-ip">${escapeHtml(node.ip)}</div>
                </div>
            </div>
            <div class="tree-children ${isCollapsed ? '' : 'expanded'}">
                ${(byParent[node.id] || []).map(child => renderNode(child, depth + 1)).join('')}
            </div>
        `;
    }
    
    const roots = byParent['__root__'] || [];
    list.innerHTML = roots.map(n => renderNode(n, 0)).join('');
    
    attachDragAndDrop();
}

function toggleNodeCollapse(nodeId) {
    if (collapsedNodes.has(nodeId)) collapsedNodes.delete(nodeId);
    else collapsedNodes.add(nodeId);
    renderTree();
}

// Drag & Drop
function attachDragAndDrop() {
    document.querySelectorAll('.tree-node').forEach(node => {
        node.addEventListener('dragstart', e => {
            draggedNodeId = node.getAttribute('data-node-id');
            e.dataTransfer.effectAllowed = 'move';
            node.classList.add('dragging');
        });
        node.addEventListener('dragend', () => node.classList.remove('dragging'));
        node.addEventListener('dragover', e => {
            e.preventDefault();
            if (node.getAttribute('data-node-id') !== draggedNodeId) node.classList.add('drag-over');
        });
        node.addEventListener('dragleave', () => node.classList.remove('drag-over'));
        node.addEventListener('drop', async e => {
            e.preventDefault();
            node.classList.remove('drag-over');
            const targetId = node.getAttribute('data-node-id');
            if (!targetId || !draggedNodeId || targetId === draggedNodeId) return;
            if (isDescendant(draggedNodeId, targetId)) {
                showNotification('Нельзя перетащить устройства в своего потомка', 'error');
                return;
            }
            await changeParent(draggedNodeId, targetId);
            draggedNodeId = null;
        });
    });
}

function isDescendant(ancestorId, nodeId) {
    let current = currentMap.data.nodes.find(n => n.id === nodeId);
    while (current && current.parent_id) {
        if (current.parent_id === ancestorId) return true;
        current = currentMap.data.nodes.find(n => n.id === current.parent_id);
    }
    return false;
}

async function changeParent(nodeId, newParentId) {
    const resp = await api(`/api/maps/${currentMap.id}/nodes/${nodeId}`, {
        method: 'PUT',
        body: JSON.stringify({ parent_id: newParentId })
    });
    if (resp && resp.ok) {
        showNotification('устройства перемещён', 'success');
        await selectMap(currentMap.id);
        // Перерисовываем граф полностью (чтобы появилось ребро)
        if (network) { network.destroy(); network = null; }
        initGraph();
    } else {
        showNotification('Ошибка перемещения', 'error');
    }
}

// ====== ГРАФ (с защитой от циклов и сбросом) ======
function initGraph() {
    if (!currentMap || !currentMap.data.nodes || currentMap.data.nodes.length === 0) {
        if (network) { network.destroy(); network = null; }
        document.getElementById('emptyState').style.display = 'block';
        return;
    }
    document.getElementById('emptyState').style.display = 'none';

    const nodeMap = Object.fromEntries(currentMap.data.nodes.map(n => [n.id, n]));

        const nodes = currentMap.data.nodes.map(n => {
        const status = n.aggregated_status || 'unknown';
        // Цвет фона по статусу
        const bgColor = {
            online:  '#4caf50',
            offline: '#cf6679',
            mixed:   '#ff9800',
            unknown: '#6b7280'
        }[status] || '#6b7280';
        
        const ips = (n.ip || '').split(',').map(s => s.trim()).filter(Boolean);
        let displayLabel = '';
        if (ips.length > 1) {
            displayLabel = `${n.name || 'Устройство'}\n(${ips.length} IP)`;
        } else {
            displayLabel = `${n.name || n.ip}\n${n.ip || ''}`;
        }
        
        const meta = n.metadata || {};
        const customIcon = meta.icon;
        const iconUrl = customIcon 
            ? `/static/icons/${customIcon}.png` 
            : null;
        
        let nodeObj;
        if (iconUrl) {
            // Иконка в цветном круге (фон = статус)
            nodeObj = {
                id: n.id,
                label: displayLabel,
                title: `IP: ${n.ip || '—'}\nТип: ${n.type || 'unknown'}\nСтатус: ${status}`,
                shape: 'circularImage',
                image: iconUrl,
                size: n.is_root ? 40 : 32,
                color: {
                    background: bgColor,
                    border: bgColor,
                    highlight: { background: bgColor, border: '#ffffff' }
                },
                borderWidth: 3,
                font: { 
                    color: '#e1e1e6', 
                    size: 11, 
                    face: 'Roboto', 
                    vadjust: 40
                }
            };
        } else {
            // Обычный бокс
            nodeObj = {
                id: n.id,
                label: displayLabel,
                title: `IP: ${n.ip || '—'}\nТип: ${n.type || 'unknown'}\nСтатус: ${status}`,
                color: { 
                    background: bgColor + '30', 
                    border: bgColor, 
                    highlight: { background: bgColor + '50', border: bgColor } 
                },
                font: { color: '#e1e1e6', size: 12, face: 'Roboto', align: 'center' },
                shape: n.is_root ? 'star' : 'box',
                borderWidth: 2
            };
        }
        
        if (typeof meta.x === 'number' && typeof meta.y === 'number' && !isNaN(meta.x) && !isNaN(meta.y)) {
            nodeObj.x = meta.x;
            nodeObj.y = meta.y;
        }
        return nodeObj;
    });

    const edges = (currentMap.data.edges || [])
        .filter(e => e && e.source && e.target && nodeMap[e.source] && nodeMap[e.target])
        .filter((e, i, arr) => arr.findIndex(x => x.source === e.source && x.target === e.target) === i)
                .map(e => {
            const targetNode = nodeMap[e.target];
            const targetStatus = targetNode?.aggregated_status || 'unknown';
            
            // Цвет по доступности: online → зелёный, offline → красный, unknown → серый
            const edgeColor = targetStatus === 'online' 
                ? 'rgba(74, 222, 128, 0.7)'
                : targetStatus === 'offline' 
                    ? 'rgba(248, 113, 113, 0.7)'
                    : 'rgba(156, 163, 175, 0.5)';
            const highlightColor = targetStatus === 'online' 
                ? '#4ade80' 
                : targetStatus === 'offline' 
                    ? '#f87171' 
                    : '#9ca3af';
            
            // Подпись: from_ip → to_ip (если есть)
            const label = (e.from_ip && e.to_ip) 
                ? `${e.from_ip} → ${e.to_ip}` 
                : undefined;
            
            // Tooltip: подробная информация
            const title = `Связь: ${e.from_ip || '?'} → ${e.to_ip || '?'}\n` +
                          `Статус: ${targetStatus}\n` +
                          `Узел: ${targetNode?.ip || '?'}`;
            
            return {
                id: e.id,
                from: e.source,
                to: e.target,
                label: label,
                title: title,
                arrows: { to: { enabled: true, scaleFactor: 0.6 } },
                color: {
                    color: edgeColor,
                    highlight: highlightColor
                },
                width: targetStatus === 'offline' ? 2.5 : 2,
                font: { 
                    color: '#c0c0c8', 
                    size: 10, 
                    background: 'rgba(26, 26, 31, 0.85)',
                    strokeWidth: 0
                },
                dashes: e.type !== 'parent-child',
                smooth: { type: 'continuous' }
            };
        });

    const container = document.getElementById('network');
    const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
    
    const options = {
        physics: { stabilization: { enabled: true, iterations: 300 }, barnesHut: { gravitationalConstant: -4000, springLength: 150 } },
        interaction: { hover: true, dragNodes: true }
    };
    
    if (network) network.destroy();
    network = new vis.Network(container, data, options);

    network.on('click', params => {
        if (params.nodes.length > 0) {
            selectNode(params.nodes[0]);
            openPropsPanel();
        } else {
            closePropsPanel();
        }
    });
    network.on('dragEnd', params => {
        if (params.nodes.length > 0) savePositionsDebounced();
    });
}

let savePositionsTimer = null;
function savePositionsDebounced() {
    if (savePositionsTimer) clearTimeout(savePositionsTimer);
    savePositionsTimer = setTimeout(savePositions, 2000);
}

async function savePositions() {
    if (!network || !currentMap) return;
    const positions = {};
    network.body.data.nodes.get().forEach(n => {
        const pos = network.getPositions([n.id])[n.id];
        if (pos && !isNaN(pos.x) && !isNaN(pos.y)) positions[n.id] = { x: pos.x, y: pos.y };
    });
    if (Object.keys(positions).length === 0) return;
    try {
        await api(`/api/maps/${currentMap.id}/positions`, { method: 'PUT', body: JSON.stringify({ positions }) });
    } catch (e) { }
}

function updateGraphData() {
    if (!network || !currentMap) return;
    const currentNodes = currentMap.data.nodes || [];
    const nodeUpdates = currentNodes.map(n => {
        const status = n.aggregated_status || 'unknown';
        const color = { online: '#4caf50', offline: '#cf6679', mixed: '#ff9800', unknown: '#6b7280' }[status] || '#6b7280';
        return {
            id: n.id,
            label: (n.name || n.ip) + '\n' + n.ip,
            color: { background: color + '30', border: color }
        };
    });
    
    const existingIds = new Set(network.body.data.nodes.getIds());
    const newNodes = currentNodes.filter(n => !existingIds.has(n.id)).map(n => {
        const status = n.aggregated_status || 'unknown';
        const color = { online: '#4caf50', offline: '#cf6679', mixed: '#ff9800', unknown: '#6b7280' }[status] || '#6b7280';
        return {
            id: n.id, label: (n.name || n.ip) + '\n' + n.ip,
            color: { background: color + '30', border: color },
            font: { color: '#e1e1e6', size: 12 },
            shape: n.is_root ? 'star' : 'box', borderWidth: 2
        };
    });

    if (nodeUpdates.length > 0) network.body.data.nodes.update(nodeUpdates);
    if (newNodes.length > 0) network.body.data.nodes.add(newNodes);
}

// ====== ВЫБОР УЗЛА ======
function selectNode(nodeId) {
    selectedNodeId = nodeId;
    selectedNode = currentMap.data.nodes.find(n => n.id === nodeId);
    if (!selectedNode) return;

    // Открываем модалку (панель + оверлей)
    openPropsPanel();

    document.getElementById('propsTitle').textContent = selectedNode.name || selectedNode.ip;
    
    // Список интерфейсов (IP-портов)
    const interfaces = selectedNode.interfaces || (selectedNode.ip ? selectedNode.ip.split(',').map(s => s.trim()) : []);
    document.getElementById('propsIp').innerHTML = interfaces.map(ip => 
        `<div style="font-family: 'JetBrains Mono', monospace; font-size: 12px; padding: 2px 0; color: #e0e0e5;">${ip}</div>`
    ).join('');
    
    document.getElementById('propsType').textContent = selectedNode.type || '—';
    document.getElementById('propsDiscovered').textContent = (selectedNode.discovered_by || []).join(', ') || '—';
    document.getElementById('propsStatus').textContent = selectedNode.aggregated_status || 'unknown';

    const checksList = document.getElementById('checksList');
    if (!selectedNode.checks || selectedNode.checks.length === 0) {
        checksList.innerHTML = '<div style="color: var(--md-on-surface-muted); font-size: 13px;">Нет проверок</div>';
    } else {
        const statuses = selectedNode.status || {};
        checksList.innerHTML = selectedNode.checks.map(c => {
            const key = c.port ? `${c.type}_${c.port}` : c.type;
            const st = statuses[key] || {};
            const cls = st.status === 'online' ? 'online' : st.status === 'offline' ? 'offline' : 'unknown';
            const lat = st.latency ? `${st.latency.toFixed(1)} ms` : '';
            return `
                <div class="check-item">
                    <span class="check-name">${c.type}${c.port ? ':' + c.port : ''}</span>
                    <span class="check-status ${cls}">${st.status || '—'} ${lat}</span>
                </div>
            `;
        }).join('');
    }

    const snmpSection = document.getElementById('snmpSection');
    const meta = selectedNode.metadata || {};
    if (meta.snmp_descr || meta.snmp_uptime || meta.snmp_name) {
        snmpSection.style.display = 'block';
        const parts = [];
        if (meta.snmp_name) parts.push(meta.snmp_name);
        if (meta.snmp_descr) parts.push(meta.snmp_descr.substring(0, 80));
        if (meta.snmp_uptime) parts.push(`uptime: ${meta.snmp_uptime}`);
        if (meta.snmp_location) parts.push(meta.snmp_location);
        document.getElementById('propsSnmp').innerHTML = parts.join('<br>');
    } else {
        snmpSection.style.display = 'none';
    }

    renderTree();
}
// ====== НОВАЯ КАРТА ======
function openNewMapModal() {
    document.getElementById('newMapModal').classList.add('show');
}

async function createMap() {
    const name = document.getElementById('newMapName').value.trim();
    const description = document.getElementById('newMapDescription').value.trim();
    const subnetsStr = document.getElementById('newMapSubnets').value.trim();
    if (!name) { showNotification('Введите название', 'error'); return; }
    const subnets = subnetsStr ? subnetsStr.split(',').map(s => s.trim()).filter(Boolean) : null;
    const resp = await api('/api/maps', {
        method: 'POST',
        body: JSON.stringify({ name, description, is_public: false, allowed_subnets: subnets })
    });
    if (!resp || !resp.ok) { showNotification('Ошибка создания', 'error'); return; }
    const data = await resp.json();
    closeModal('newMapModal');
    showNotification('Карта создана', 'success');
    await loadMaps();
    await selectMap(data.map_id);
}

// ====== СКАНИРОВАНИЕ ======
function openScanModal() {
    if (!currentMap) { showNotification('Сначала выберите карту', 'warning'); return; }
    document.getElementById('scanProgress').style.display = 'none';
    document.getElementById('scanStartBtn').disabled = false;
    document.getElementById('scanModal').classList.add('show');
}

async function startScan() {
    const rootIp = document.getElementById('scanRootIp').value.trim();
    const hops = parseInt(document.getElementById('scanHops').value) || 2;
    const subnet = document.getElementById('scanSubnet').value.trim() || null;
    if (!rootIp) { showNotification('Введите корневой IP', 'error'); return; }

    const btn = document.getElementById('scanStartBtn');
    btn.disabled = true;
    document.getElementById('scanProgress').style.display = 'block';
    const methods = ['arp', 'icmp', 'traceroute'];
    if (document.getElementById('scanUseSnmp').checked) methods.push('snmp');
    const resp = await api(`/api/maps/${currentMap.id}/scan`, {
        method: 'POST',
        body: JSON.stringify({ root_ip: rootIp, hops, subnet, methods })
    });
    if (!resp || !resp.ok) {
        showNotification('Ошибка запуска сканирования', 'error');
        btn.disabled = false;
        return;
    }
    const { job_id } = await resp.json();
    pollScan(job_id);
}

async function pollScan(jobId) {
    const interval = setInterval(async () => {
        const resp = await api(`/api/maps/${currentMap.id}/scan/${jobId}`);
        if (!resp) { clearInterval(interval); return; }
        const data = await resp.json();
        document.getElementById('scanProgressFill').style.width = data.progress + '%';
        document.getElementById('scanProgressText').textContent = data.progress + '%';
        if (data.status === 'done') {
            clearInterval(interval);
            closeModal('scanModal');
            showNotification(`Сканирование завершено: ${data.result.nodes_count} узлов`, 'success');
            await selectMap(currentMap.id);
        } else if (data.status === 'error') {
            clearInterval(interval);
            showNotification('Ошибка сканирования: ' + (data.error || ''), 'error');
            document.getElementById('scanStartBtn').disabled = false;
        }
    }, 1000);
}

// ====== МОДАЛКИ ======
function closeModal(id) {
    document.getElementById(id).classList.remove('show');
}

// ====== ВЫХОД ======
function logout() {
    if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_info');
    window.location.href = '/login';
}

// ====== УДАЛЕНИЕ КАРТЫ ======
async function deleteCurrentMap() {
    if (!currentMap) { showNotification('Сначала выберите карту', 'warning'); return; }
    if (!confirm(`Удалить карту "${currentMap.name}"? Это действие нельзя отменить!`)) return;

    const resp = await api(`/api/maps/${currentMap.id}`, { method: 'DELETE' });
    if (!resp || !resp.ok) {
        let err = 'Ошибка удаления';
        try { const e = await resp.json(); err = e.detail || err; } catch {}
        showNotification(err, 'error');
        return;
    }

    showNotification(`Карта "${currentMap.name}" удалена`, 'success');
    currentMap = null;
    selectedNode = null;
    selectedNodeId = null;
    document.getElementById('propsPanel').classList.remove('show');
    document.getElementById('currentMapBar').style.display = 'none';
    document.getElementById('emptyState').style.display = 'block';
    document.getElementById('treeList').innerHTML = 
        '<div style="color: var(--md-on-surface-muted); font-size: 13px; text-align: center; padding: 20px;">Выберите карту</div>';
    if (network) { network.destroy(); network = null; }
    await loadMaps();
    const mapsResp = await api('/api/maps');
    if (mapsResp) {
        const data = await mapsResp.json();
        if (data.maps && data.maps.length > 0) await selectMap(data.maps[0].id);
    }
}

// ====== ПЕРЕИМЕНОВАНИЕ КАРТЫ ======
async function openRenameMapModal() {
    if (!currentMap) { showNotification('Сначала выберите карту', 'warning'); return; }
    const newName = prompt('Новое название карты:', currentMap.name || '');
    if (newName === null || newName.trim() === '' || newName === currentMap.name) return;
    const resp = await api(`/api/maps/${currentMap.id}`, {
        method: 'PUT',
        body: JSON.stringify({ name: newName.trim() })
    });
    if (!resp || !resp.ok) { showNotification('Ошибка переименования', 'error'); return; }
    showNotification('Карта переименована', 'success');
    await selectMap(currentMap.id);
}

// ====== ИСТОРИЯ ======
let historyChart = null;
let currentHistoryHours = 24;

function openHistory() {
    if (!selectedNode) { showNotification('Сначала выберите устройства', 'warning'); return; }
    if (historyChart) { historyChart.destroy(); historyChart = null; }
    document.getElementById('historyTitle').textContent = 
        `История: ${selectedNode.name || selectedNode.ip}`;
    document.getElementById('historyModal').classList.add('show');
    loadHistory(24);
}

async function loadHistory(hours) {
    if (!selectedNode) return;
    currentHistoryHours = hours;
    const resp = await api(`/api/maps/${currentMap.id}/nodes/${selectedNode.id}/history?hours=${hours}`);
    if (!resp || !resp.ok) { showNotification('Ошибка загрузки истории', 'error'); return; }
    const data = await resp.json();
    document.getElementById('histUptime').textContent = data.stats.uptime_percent + '%';
    document.getElementById('histAvg').textContent = data.stats.avg_latency + ' ms';
    document.getElementById('histChecks').textContent = data.stats.total;
    document.getElementById('histOffline').textContent = data.stats.offline;
    drawHistoryChart(data.history);
}

function drawHistoryChart(history) {
    const canvas = document.getElementById('historyChart');
    if (!canvas) return;
    if (historyChart) { historyChart.destroy(); historyChart = null; }
    if (!history || history.length === 0) {
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = 'rgba(138, 138, 148, 0.5)';
        ctx.font = '14px Roboto, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('Нет данных за выбранный период', canvas.width / 2, 150);
        return;
    }
    const labels = history.map(h => new Date(h.timestamp).toLocaleTimeString());
    const latency = history.map(h => h.status === 'online' ? h.latency : null);
    const ctx = canvas.getContext('2d');
    historyChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Latency (ms)',
                data: latency,
                borderColor: '#bb86fc',
                backgroundColor: 'rgba(187, 134, 252, 0.1)',
                tension: 0.3,
                fill: true,
                spanGaps: true,
                pointRadius: 2,
                pointBackgroundColor: '#bb86fc'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#e1e1e6' } } },
            scales: {
                y: { beginAtZero: true, ticks: { color: 'rgba(225, 225, 230, 0.5)' }, grid: { color: 'rgba(225, 225, 230, 0.05)' } },
                x: { ticks: { color: 'rgba(225, 225, 230, 0.5)', maxTicksLimit: 10 }, grid: { display: false } }
            }
        }
    });
}

// ====== ДОБАВЛЕНИЕ УЗЛА ======
function openAddNodeModal() {
    if (!currentMap) { showNotification('Сначала выберите карту', 'warning'); return; }
    document.getElementById('addNodeIp').value = '';
    document.getElementById('addNodeName').value = '';
    document.getElementById('addNodeType').value = 'unknown';
    document.getElementById('addCheckIcmp').checked = true;
    document.getElementById('addCheckTcp').checked = false;
    document.getElementById('addCheckTcpPort').value = '22';
    document.getElementById('addCheckSnmp').checked = false;

    const select = document.getElementById('addNodeParent');
    select.innerHTML = '<option value="">— Корень карты —</option>';
    if (currentMap.data.nodes) {
        currentMap.data.nodes.forEach(n => {
            const opt = document.createElement('option');
            opt.value = n.id;
            opt.textContent = `${n.name || n.ip} (${n.ip})`;
            select.appendChild(opt);
        });
    }
    document.getElementById('addNodeModal').classList.add('show');
}

async function addNode() {
    const ip = document.getElementById('addNodeIp').value.trim();
    const name = document.getElementById('addNodeName').value.trim();
    const type = document.getElementById('addNodeType').value;
    const parentId = document.getElementById('addNodeParent').value || null;
    const useIcmp = document.getElementById('addCheckIcmp').checked;
    const useTcp = document.getElementById('addCheckTcp').checked;
    const tcpPort = parseInt(document.getElementById('addCheckTcpPort').value) || 22;
    const useSnmp = document.getElementById('addCheckSnmp').checked;

    if (!ip) { showNotification('Введите IP-адрес', 'error'); return; }

    const checks = [];
    if (useIcmp) checks.push({ type: 'icmp', timeout: 2 });
    if (useTcp) checks.push({ type: 'tcp', port: tcpPort, timeout: 3 });
    if (useSnmp) checks.push({ type: 'snmp', timeout: 3 });
    if (checks.length === 0) { showNotification('Выберите хотя бы одну проверку', 'error'); return; }

    const btn = document.getElementById('addNodeBtn');
    btn.disabled = true;
    const resp = await api(`/api/maps/${currentMap.id}/nodes`, {
        method: 'POST',
        body: JSON.stringify({ ip, name: name || null, type, parent_id: parentId, checks })
    });
    btn.disabled = false;

    if (!resp || !resp.ok) {
        let err = 'Ошибка добавления';
        try { const e = await resp.json(); err = e.detail || err; } catch {}
        showNotification(err, 'error');
        return;
    }
    const data = await resp.json();
    closeModal('addNodeModal');
    if (data.is_outside_whitelist) {
        showNotification('устройства добавлен вне whitelist', 'warning');
    } else {
        showNotification(`устройства ${ip} добавлен`, 'success');
    }
    await selectMap(currentMap.id);
}

// ====== РЕДАКТИРОВАНИЕ ПРОВЕРОК ======
function openChecksEditor() {
    if (!selectedNode) { showNotification('Сначала выберите устройства', 'warning'); return; }
    document.getElementById('checksModalTitle').textContent = 
        `Проверки: ${selectedNode.name || selectedNode.ip}`;
    document.getElementById('chkIcmpEnabled').checked = false;
    document.getElementById('chkTcpEnabled').checked = false;
    document.getElementById('chkUdpEnabled').checked = false;
    document.getElementById('chkSnmpEnabled').checked = false;
    (selectedNode.checks || []).forEach(c => {
        if (c.type === 'icmp') {
            document.getElementById('chkIcmpEnabled').checked = c.enabled !== false;
            document.getElementById('chkIcmpTimeout').value = c.timeout || 2;
        } else if (c.type === 'tcp') {
            document.getElementById('chkTcpEnabled').checked = c.enabled !== false;
            document.getElementById('chkTcpPort').value = c.port || 22;
            document.getElementById('chkTcpTimeout').value = c.timeout || 3;
        } else if (c.type === 'udp') {
            document.getElementById('chkUdpEnabled').checked = c.enabled !== false;
            document.getElementById('chkUdpPort').value = c.port || 53;
            document.getElementById('chkUdpTimeout').value = c.timeout || 3;
        } else if (c.type === 'snmp') {
            document.getElementById('chkSnmpEnabled').checked = c.enabled !== false;
            document.getElementById('chkSnmpTimeout').value = c.timeout || 3;
        }
    });
    document.getElementById('checksModal').classList.add('show');
}

async function saveChecks() {
    if (!selectedNode) return;
    const checks = [];
    if (document.getElementById('chkIcmpEnabled').checked) {
        checks.push({ type: 'icmp', enabled: true, timeout: parseInt(document.getElementById('chkIcmpTimeout').value) || 2 });
    }
    if (document.getElementById('chkTcpEnabled').checked) {
        checks.push({ type: 'tcp', port: parseInt(document.getElementById('chkTcpPort').value) || 22, enabled: true, timeout: parseInt(document.getElementById('chkTcpTimeout').value) || 3 });
    }
    if (document.getElementById('chkUdpEnabled').checked) {
        checks.push({ type: 'udp', port: parseInt(document.getElementById('chkUdpPort').value) || 53, enabled: true, timeout: parseInt(document.getElementById('chkUdpTimeout').value) || 3 });
    }
    if (document.getElementById('chkSnmpEnabled').checked) {
        checks.push({ type: 'snmp', enabled: true, timeout: parseInt(document.getElementById('chkSnmpTimeout').value) || 3 });
    }
    if (checks.length === 0) { showNotification('Выберите хотя бы одну проверку', 'error'); return; }

    const btn = document.getElementById('saveChecksBtn');
    btn.disabled = true;
    const resp = await api(`/api/maps/${currentMap.id}/nodes/${selectedNode.id}/checks`, {
        method: 'PUT',
        body: JSON.stringify({ checks })
    });
    btn.disabled = false;
    if (!resp || !resp.ok) { showNotification('Ошибка сохранения', 'error'); return; }
    closeModal('checksModal');
    showNotification('Проверки обновлены', 'success');
    await selectMap(currentMap.id);
    setTimeout(() => selectNode(selectedNode.id), 100);
}

// ====== АВТООБНОВЛЕНИЕ ======
function toggleAutoRefresh() {
    autoRefreshEnabled = !autoRefreshEnabled;
    const btn = document.getElementById('autoRefreshBtn');
    if (autoRefreshEnabled) {
        if (!currentMap) {
            showNotification('Сначала выберите карту', 'warning');
            autoRefreshEnabled = false;
            return;
        }
        btn.textContent = `Авто (${AUTO_REFRESH_INTERVAL}с)`;
        btn.style.background = 'var(--md-secondary-container)';
        btn.style.color = 'var(--md-secondary)';
        autoRefreshTimer = setInterval(refreshMapSilent, AUTO_REFRESH_INTERVAL * 1000);
        showNotification(`Автообновление включено (каждые ${AUTO_REFRESH_INTERVAL} сек)`, 'success');
    } else {
        btn.textContent = 'Авто';
        btn.style.background = '';
        btn.style.color = '';
        if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
        showNotification('Автообновление выключено', 'info');
    }
}

async function refreshMapSilent() {
    if (!currentMap || !autoRefreshEnabled) return;
    
    // Адаптивный интервал
    const nodeCount = (currentMap.data.nodes || []).length;
    const newInterval = calculateRefreshInterval(nodeCount);
    if (newInterval !== currentRefreshInterval) {
        currentRefreshInterval = newInterval;
        if (autoRefreshTimer) clearInterval(autoRefreshTimer);
        autoRefreshTimer = setInterval(refreshMapSilent, newInterval);
        console.log(`[auto-refresh] ${nodeCount} узлов → ${newInterval / 1000}с`);
    }
    
    try {
        const resp = await api(`/api/maps/${currentMap.id}`);
        if (!resp || !resp.ok) return;
        const newMap = await resp.json();
        const newNodes = newMap.data.nodes || [];
        
        // Сохраняем текущие устройства (чтобы не терять позиции)
        const existingIds = new Set(network.body.data.nodes.getIds());
        const newNodeIds = new Set(newNodes.map(n => n.id));
        
        // 1. Обновляем существующие устройства (только цвет/статус)
        const updates = newNodes.filter(n => existingIds.has(n.id)).map(n => {
            const status = n.aggregated_status || 'unknown';
            const bgColor = { 
                online: '#4caf50', 
                offline: '#cf6679', 
                mixed: '#ff9800', 
                unknown: '#6b7280' 
            }[status] || '#6b7280';
            
            const meta = n.metadata || {};
            const hasIcon = !!meta.icon;
            
            if (hasIcon) {
                // circularImage — меняем только цвет фона
                return {
                    id: n.id,
                    color: { 
                        background: bgColor, 
                        border: bgColor, 
                        highlight: { background: bgColor, border: '#ffffff' } 
                    }
                };
            } else {
                // обычный бокс — меняем цвет
                return {
                    id: n.id,
                    color: { 
                        background: bgColor + '30', 
                        border: bgColor, 
                        highlight: { background: bgColor + '50', border: bgColor } 
                    }
                };
            }
        });
        if (updates.length > 0) network.body.data.nodes.update(updates);
        
        // 2. Удаляем устройства, которых больше нет (если сканирование удалило)
        const toRemove = [...existingIds].filter(id => !newNodeIds.has(id));
        if (toRemove.length > 0) network.body.data.nodes.remove(toRemove);
        
        // 3. Добавляем новые устройства (если появились)
        const toAdd = newNodes.filter(n => !existingIds.has(n.id)).map(n => {
            const status = n.aggregated_status || 'unknown';
            const color = { online: '#4caf50', offline: '#cf6679', mixed: '#ff9800', unknown: '#6b7280' }[status] || '#6b7280';
            const ips = (n.ip || '').split(',').map(s => s.trim()).filter(Boolean);
            let label = ips.length > 1 
                ? `${n.name || 'Устройство'}\n(${ips.length} IP)` 
                : `${n.name || n.ip}\n${n.ip || ''}`;
            return {
                id: n.id,
                label: label,
                title: 'IP: ' + (n.ip || '—') + '\nТип: ' + (n.type || 'unknown'),
                color: { background: color + '30', border: color },
                font: { color: '#e1e1e6', size: 12, face: 'Roboto', align: 'center' },
                shape: n.is_root ? 'star' : 'box',
                borderWidth: 2
            };
        });
        if (toAdd.length > 0) network.body.data.nodes.add(toAdd);
        
        // 4. Обновляем рёбра (с правильным цветом и подписями)
        const newNodeMap = Object.fromEntries(newNodes.map(n => [n.id, n]));
        const newEdges = (newMap.data.edges || [])
            .filter(e => e && e.source && e.target && newNodeMap[e.source] && newNodeMap[e.target])
            .filter((e, i, arr) => arr.findIndex(x => x.source === e.source && x.target === e.target) === i)
            .map(e => {
                const targetNode = newNodeMap[e.target];
                const targetStatus = targetNode?.aggregated_status || 'unknown';
                
                const edgeColor = targetStatus === 'online' 
                    ? 'rgba(74, 222, 128, 0.7)'
                    : targetStatus === 'offline' 
                        ? 'rgba(248, 113, 113, 0.7)'
                        : 'rgba(156, 163, 175, 0.5)';
                const highlightColor = targetStatus === 'online' 
                    ? '#4ade80' 
                    : targetStatus === 'offline' 
                        ? '#f87171' 
                        : '#9ca3af';
                const label = (e.from_ip && e.to_ip) ? `${e.from_ip} → ${e.to_ip}` : undefined;
                return {
                    id: e.id,
                    from: e.source,
                    to: e.target,
                    label: label,
                    title: (e.from_ip && e.to_ip) 
                        ? `Порт: ${e.from_ip} → ${e.to_ip}` 
                        : `Связь: ${e.source} → ${e.target}`,
                    arrows: { to: { enabled: true, scaleFactor: 0.6 } },
                    color: {
                        color: edgeColor,
                        highlight: highlightColor
                    },
                    width: 2,
                    font: { color: '#9d9db4', size: 10, background: 'rgba(26, 26, 31, 0.85)', strokeWidth: 0 },
                    dashes: e.type !== 'parent-child',
                    smooth: { type: 'continuous' }
                };
            });
        network.body.data.edges.clear();
        network.body.data.edges.add(newEdges);
        
        currentMap = newMap;
        renderTree();
        loadMapStats();
        
        // НЕ вызываем loadMaps (список карт не изменился)
        // НЕ вызываем initGraph (позиции сохраняются)
        
    } catch (e) {
        console.debug('Auto-refresh error:', e);
    }
}

// ====== РЕДАКТИРОВАНИЕ УЗЛА ======
function openEditNodeModal() {
    if (!selectedNode) { showNotification('Сначала выберите устройства', 'warning'); return; }
    
    document.getElementById('editNodeTitle').textContent = 
        `Редактировать: ${selectedNode.name || selectedNode.ip}`;
    document.getElementById('editNodeIp').value = selectedNode.ip;
    document.getElementById('editNodeName').value = selectedNode.name || '';
    document.getElementById('editNodeType').value = selectedNode.type || 'unknown';

    // Заполняем список родителей (все устройства, кроме самого себя и потомков)
    const select = document.getElementById('editNodeParent');
    select.innerHTML = '<option value="">— Корень карты —</option>';
    
    function isDescendant(candidateId, nodeId, nodes) {
        let current = nodes.find(n => n.id === candidateId);
        while (current && current.parent_id) {
            if (current.parent_id === nodeId) return true;
            current = nodes.find(n => n.id === current.parent_id);
        }
        return false;
    }
    
    (currentMap.data.nodes || []).forEach(n => {
        if (n.id === selectedNode.id) return;
        if (isDescendant(n.id, selectedNode.id, currentMap.data.nodes)) return;
        const opt = document.createElement('option');
        opt.value = n.id;
        opt.textContent = `${n.name || n.ip} (${n.ip})`;
        if (selectedNode.parent_id === n.id) opt.selected = true;
        select.appendChild(opt);
    });
    
    // Показать/скрыть блок IP-портов
    refreshParentIps();
    
    // Инициализация выбора иконки
    const currentIcon = (selectedNode.metadata && selectedNode.metadata.icon) || null;
    selectedIconForNode = currentIcon;
    document.querySelectorAll('#editNodeIconPicker .icon-option').forEach(opt => {
        opt.classList.toggle('selected', opt.getAttribute('data-icon') === (currentIcon || ''));
    });
    initIconPicker();
    
    document.getElementById('editNodeModal').classList.add('show');
}

function refreshParentIps() {
    const parentId = document.getElementById('editNodeParent').value;
    const group = document.getElementById('parentIpGroup');
    const select = document.getElementById('editNodeParentIp');
    
    if (!parentId) {
        group.style.display = 'none';
        return;
    }
    
    const parent = currentMap.data.nodes.find(n => n.id === parentId);
    if (!parent) {
        group.style.display = 'none';
        return;
    }
    
    const interfaces = parent.interfaces || (parent.ip ? parent.ip.split(',').map(s => s.trim()) : []);
    select.innerHTML = interfaces.map(ip => 
        `<option value="${ip}">${ip}</option>`
    ).join('');
    
    // Если устройства уже был привязан к какому-то IP — выберем его
    if (selectedNode && selectedNode.parent_ip) {
        select.value = selectedNode.parent_ip;
    }
    
    group.style.display = 'block';
}

async function saveEditedNode() {
    if (!selectedNode) return;
    const newIp = document.getElementById('editNodeIp').value.trim();
    const newName = document.getElementById('editNodeName').value.trim();
    const newType = document.getElementById('editNodeType').value;
    const newParent = document.getElementById('editNodeParent').value || null;
    const newParentIp = document.getElementById('editNodeParentIp').value || null;
    
    console.log('[saveEditedNode] parent_id:', newParent, 'parent_ip:', newParentIp);
    
    if (!newIp) { showNotification('Введите IP', 'error'); return; }
    
    const btn = document.getElementById('saveEditedNodeBtn');
    btn.disabled = true;
    const body = {};
    if (newIp !== selectedNode.ip) body.ip = newIp;
    if (newName !== (selectedNode.name || '')) body.name = newName;
    if (newType !== selectedNode.type) body.type = newType;
    if (newParent !== selectedNode.parent_id) body.parent_id = newParent;
    if (newParentIp !== (selectedNode.parent_ip || null)) body.parent_ip = newParentIp;
    
    console.log('[saveEditedNode] body:', body);
    // Сохраняем иконку (если изменилась)
    const currentIcon = (selectedNode.metadata && selectedNode.metadata.icon) || null;
    if (selectedIconForNode !== currentIcon) {
        await saveNodeIcon(selectedIconForNode);
    }
    
    if (Object.keys(body).length === 0) {
        closeModal('editNodeModal');
        btn.disabled = false;
        if (selectedIconForNode !== currentIcon) {
            await selectMap(currentMap.id);
        }
        return;
    }
    const resp = await api(`/api/maps/${currentMap.id}/nodes/${selectedNode.id}`, {
        method: 'PUT',
        body: JSON.stringify(body)
    });
    btn.disabled = false;
    if (!resp || !resp.ok) {
        let err = 'Ошибка сохранения';
        try { const e = await resp.json(); err = e.detail || err; } catch {}
        showNotification(err, 'error');
        return;
    }
    const data = await resp.json();
    closeModal('editNodeModal');
    showNotification('устройства обновлён', 'success');
    const newSelectedId = data.node_id;
    await selectMap(currentMap.id);
    setTimeout(() => selectNode(newSelectedId), 200);
}

// ====== УДАЛЕНИЕ УЗЛА ======
async function deleteSelectedNode() {
    if (!selectedNode) return;
    if (!confirm(`Удалить устройства "${selectedNode.name || selectedNode.ip}"?`)) return;
    const resp = await api(`/api/maps/${currentMap.id}/nodes/${selectedNode.id}`, { method: 'DELETE' });
    if (!resp || !resp.ok) { showNotification('Ошибка удаления', 'error'); return; }
    showNotification('устройства удалён', 'success');
    document.getElementById('propsPanel').classList.remove('show');
    selectedNode = null;
    selectedNodeId = null;
    await selectMap(currentMap.id);
}

// ====== ЭКСПОРТ ======
async function exportCurrentMap() {
    if (!currentMap) { showNotification('Сначала выберите карту', 'warning'); return; }
    const resp = await api(`/api/maps/${currentMap.id}/export`);
    if (!resp || !resp.ok) { showNotification('Ошибка экспорта', 'error'); return; }
    const data = await resp.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const safeName = (currentMap.name || 'map').replace(/[^a-zA-Z0-9_\-а-яА-ЯёЁ]/g, '_');
    a.download = `${safeName}_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showNotification('Экспорт завершён', 'success');
}

// ====== ИМПОРТ ======
let importPayload = null;

function openImportModal() {
    importPayload = null;
    document.getElementById('importFile').value = '';
    document.getElementById('importPreview').style.display = 'none';
    document.getElementById('confirmImportBtn').disabled = true;
    document.getElementById('importModal').classList.add('show');
}

function onImportFileSelected(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const data = JSON.parse(e.target.result);
            let mapObj;
            if (data.type === 'horizon_tree_map' && data.map) {
                mapObj = data.map;
            } else if (data.nodes) {
                mapObj = {
                    name: file.name.replace('.json', ''),
                    description: 'Импортировано из ' + file.name,
                    is_public: false,
                    allowed_subnets: [],
                    data: data
                };
            } else {
                throw new Error('Неверный формат файла');
            }
            importPayload = {
                name: mapObj.name || file.name.replace('.json', ''),
                description: mapObj.description || '',
                is_public: mapObj.is_public || false,
                allowed_subnets: mapObj.allowed_subnets || [],
                data: mapObj.data
            };
            document.getElementById('importName').textContent = importPayload.name;
            document.getElementById('importNodes').textContent = (importPayload.data.nodes || []).length;
            document.getElementById('importEdges').textContent = (importPayload.data.edges || []).length;
            document.getElementById('importPreview').style.display = 'block';
            document.getElementById('confirmImportBtn').disabled = false;
        } catch (err) {
            showNotification('Ошибка чтения файла: ' + err.message, 'error');
            importPayload = null;
            document.getElementById('confirmImportBtn').disabled = true;
        }
    };
    reader.readAsText(file);
}

async function confirmImport() {
    if (!importPayload) { showNotification('Сначала выберите файл', 'warning'); return; }
    const btn = document.getElementById('confirmImportBtn');
    btn.disabled = true;
    const resp = await api('/api/maps/import', {
        method: 'POST',
        body: JSON.stringify(importPayload)
    });
    btn.disabled = false;
    if (!resp || !resp.ok) {
        let err = 'Ошибка импорта';
        try { const e = await resp.json(); err = e.detail || err; } catch {}
        showNotification(err, 'error');
        return;
    }
    const data = await resp.json();
    closeModal('importModal');
    showNotification(`Импортировано: ${data.nodes_count} узлов`, 'success');
    await loadMaps();
    await selectMap(data.map_id);
}
// ====== СВЯЗЫВАНИЕ КОРНЕЙ ======
function openLinkRootsModal() {
    if (!currentMap) {
        showNotification('Сначала выберите карту', 'warning');
        return;
    }

    const roots = (currentMap.data.nodes || []).filter(n => n.is_root);
    if (roots.length < 2) {
        showNotification('Нужно минимум 2 корня (запустите сканирование)', 'warning');
        return;
    }

    const sourceSelect = document.getElementById('linkSourceRoot');
    const targetSelect = document.getElementById('linkTargetRoot');

    const options = roots.map(n => 
        `<option value="${n.id}">${escapeHtml(n.name || n.ip)} (${escapeHtml(n.ip)})</option>`
    ).join('');

    sourceSelect.innerHTML = options;
    targetSelect.innerHTML = options;

    // Target не должен быть равен source по умолчанию
    if (roots.length >= 2) {
        targetSelect.value = roots[1].id;
    }

    document.getElementById('linkNote').value = '';
    document.getElementById('linkRootsModal').classList.add('show');
}

async function linkRoots() {
    const sourceId = document.getElementById('linkSourceRoot').value;
    const targetId = document.getElementById('linkTargetRoot').value;
    const linkType = document.getElementById('linkType').value;
    const note = document.getElementById('linkNote').value.trim();

    if (!sourceId || !targetId) {
        showNotification('Выберите оба корня', 'error');
        return;
    }
    if (sourceId === targetId) {
        showNotification('Нельзя связать корень с собой', 'error');
        return;
    }

    const btn = document.getElementById('linkRootsBtn');
    btn.disabled = true;

    const resp = await api(`/api/maps/${currentMap.id}/link-roots`, {
        method: 'POST',
        body: JSON.stringify({
            source_root_id: sourceId,
            target_root_id: targetId,
            link_type: linkType,
            note: note || null
        })
    });

    btn.disabled = false;

    if (!resp || !resp.ok) {
        let err = 'Ошибка связывания';
        try { const e = await resp.json(); err = e.detail || err; } catch {}
        showNotification(err, 'error');
        return;
    }

    closeModal('linkRootsModal');
    showNotification('Корни связаны!', 'success');
    await selectMap(currentMap.id);
}
// ====== ИНИЦИАЛИЗАЦИЯ ======
async function init() {
    if (!token) { window.location.href = '/login'; return; }
    await loadUser();
    await loadMaps();
    const resp = await api('/api/maps');
    if (resp) {
        const data = await resp.json();
        if (data.maps && data.maps.length > 0) {
            await selectMap(data.maps[0].id);
        }
    }
}

// Функция расчёта интервала
function calculateRefreshInterval(nodeCount) {
    if (nodeCount <= 30) return 5000;
    if (nodeCount <= 50) return 10000;
    if (nodeCount <= 100) return 15000;
    if (nodeCount <= 200) return 30000;
    return 60000;
}

init();

// Автообновление всегда включено с адаптивным интервалом
autoRefreshEnabled = true;
let currentRefreshInterval = 5000; // дефолт для малого числа узлов
autoRefreshTimer = setInterval(refreshMapSilent, currentRefreshInterval);

// ============================================================
// СЛИЯНИЕ УЗЛОВ
// ============================================================

function openMergeModal() {
    if (!currentMap) { showNotification('Сначала выберите карту', 'warning'); return; }
    const list = document.getElementById('mergeNodeList');
    const nodes = currentMap.data.nodes || [];
    if (nodes.length < 2) {
        showNotification('Нужно минимум 2 узла для объединения', 'warning');
        return;
    }
    list.innerHTML = nodes.map(n => `
        <label style="display:flex; align-items:center; gap:8px; padding:6px; cursor:pointer;">
            <input type="checkbox" value="${n.id}" class="merge-node-cb">
            <span style="color: var(--md-on-surface);">${escapeHtml(n.name || n.ip)}</span>
            <span style="color: var(--md-on-surface-muted); font-size:12px;">${escapeHtml(n.ip)}</span>
            <span style="color: var(--md-on-surface-muted); font-size:11px;">${n.type || ''}</span>
        </label>
    `).join('');
    
    document.getElementById('mergeName').value = '';
    document.getElementById('mergeVendor').value = '';
    document.getElementById('mergeModel').value = '';
    document.getElementById('mergeModal').classList.add('show');
}

async function doMerge() {
    const checks = Array.from(document.querySelectorAll('.merge-node-cb:checked')).map(cb => cb.value);
    if (checks.length < 2) { showNotification('Выберите минимум 2 узла', 'error'); return; }
    const name = document.getElementById('mergeName').value.trim();
    if (!name) { showNotification('Введите название устройства', 'error'); return; }
    
    const payload = {
        map_id: currentMap.id,
        node_ids: checks,
        name: name,
        type: document.getElementById('mergeType').value,
        vendor: document.getElementById('mergeVendor').value.trim() || null,
        model: document.getElementById('mergeModel').value.trim() || null
    };
    
    const resp = await api(`/api/maps/${currentMap.id}/devices/merge`, {
        method: 'POST',
        body: JSON.stringify(payload)
    });
    
    if (!resp || !resp.ok) { showNotification('Ошибка объединения', 'error'); return; }
    
    closeModal('mergeModal');
    showNotification(`устройства объединены в ${name}`, 'success');
    
    // Перезагружаем карту и граф
    await selectMap(currentMap.id);
    if (network) { network.destroy(); network = null; }
    initGraph();
}
// ============================================================
// АВТО-СЛИЯНИЕ
// ============================================================

async function autoMerge() {
    if (!currentMap) { showNotification('Сначала выберите карту', 'warning'); return; }
    
    const suggestions = currentMap.data.merge_suggestions || [];
    if (suggestions.length === 0) {
        showNotification('Программа не нашла узлов для авто-объединения', 'info');
        return;
    }

    if (!confirm(`Программа предлагает объединить ${suggestions.length} групп(ы) узлов. Продолжить?`)) return;

    let successCount = 0;
        for (const group of suggestions) {
        // group — это массив IP: ["10.0.0.1", "10.0.0.3"]
        const name = `Auto-Device-${Math.floor(Math.random() * 1000)}`;
        const payload = {
            map_id: currentMap.id,
            node_ids: group.map(ip => `node-${ip.replace(/\./g, '-')}`),
            name: name,
            type: 'router'
        };
        const resp = await api(`/api/maps/${currentMap.id}/devices/merge`, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        if (resp && resp.ok) successCount++;
    }


    if (successCount > 0) {
        showNotification(`Автоматически объединено ${successCount} устройств!`, 'success');
        await selectMap(currentMap.id);
        if (network) { network.destroy(); network = null; }
        initGraph();
    } else {
        showNotification('Не удалось объединить устройства (возможно, они уже объединены)', 'error');
    }
}
function closePropsPanel() {
    document.getElementById('propsPanel').classList.remove('show');
    document.getElementById('propsOverlay').classList.remove('show');
    selectedNodeId = null;
    selectedNode = null;
}

function openPropsPanel() {
    document.getElementById('propsPanel').classList.add('show');
    document.getElementById('propsOverlay').classList.add('show');
}

function toggleDropdown(event) {
    event.stopPropagation();
    const menu = document.getElementById('mainDropdown');
    menu.classList.toggle('show');
}

function closeDropdown() {
    const menu = document.getElementById('mainDropdown');
    if (menu) menu.classList.remove('show');
}

// Закрываем дропдаун при клике вне его
document.addEventListener('click', (e) => {
    const dropdown = e.target.closest('.dropdown');
    if (!dropdown) closeDropdown();
});
function openEditInterfacesModal() {
    if (!selectedNode) return;
    const interfaces = selectedNode.interfaces || (selectedNode.ip ? selectedNode.ip.split(',').map(s => s.trim()) : []);
    document.getElementById('editInterfacesList').value = interfaces.join('\n');
    document.getElementById('editInterfacesModal').classList.add('show');
}

async function saveInterfaces() {
    if (!selectedNode) return;
    const raw = document.getElementById('editInterfacesList').value;
    const interfaces = raw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
    
    if (interfaces.length === 0) {
        showNotification('Введите хотя бы один IP', 'error');
        return;
    }
    
    const resp = await api(`/api/maps/${currentMap.id}/nodes/${selectedNode.id}/interfaces`, {
        method: 'PUT',
        body: JSON.stringify({ interfaces })
    });
    
    if (!resp || !resp.ok) {
        showNotification('Ошибка сохранения', 'error');
        return;
    }
    
    closeModal('editInterfacesModal');
    closePropsPanel();
    showNotification('Интерфейсы обновлены', 'success');
    
    // Перезагружаем карту
    await selectMap(currentMap.id);
}

// ============================================================
// СТАТИСТИКА ПО КАРТЕ
// ============================================================
async function loadMapStats() {
    if (!currentMap) return;
    
    try {
        const resp = await api(`/api/maps/${currentMap.id}/stats`);
        if (!resp || !resp.ok) return;
        
        const stats = await resp.json();
        const nodes = stats.nodes || {};
        const checks = stats.checks_24h || {};
        
        const totalEl = document.querySelector('.stat-total');
        const onlineEl = document.querySelector('.stat-online');
        const mixedEl = document.querySelector('.stat-mixed');
        const offlineEl = document.querySelector('.stat-offline');
        const uptimeEl = document.querySelector('.stat-uptime');
        
        if (totalEl) totalEl.textContent = `${nodes.total || 0} узлов`;
        
        if (onlineEl) {
            onlineEl.textContent = `${nodes.online || 0} online`;
            onlineEl.title = `Все IP online: ${nodes.online || 0}`;
        }
        
        if (mixedEl) {
            const mixed = nodes.mixed || 0;
            mixedEl.textContent = `${mixed} mixed`;
            mixedEl.style.display = mixed > 0 ? 'inline-flex' : 'none';
            mixedEl.title = `Часть IP offline: ${mixed}`;
        }
        
        if (offlineEl) {
            offlineEl.textContent = `${nodes.offline || 0} offline`;
            offlineEl.title = `Все IP offline: ${nodes.offline || 0}`;
        }
        
        if (uptimeEl) {
            uptimeEl.textContent = `uptime ${checks.uptime_percent || 0}%`;
            uptimeEl.title = 
                `За 24 часа:\n` +
                `Проверок: ${checks.total || 0}\n` +
                `Online: ${checks.online || 0}\n` +
                `Ср. latency: ${checks.avg_latency_ms || 0} ms\n` +
                `Последняя проверка: ${stats.last_check ? new Date(stats.last_check).toLocaleString() : '—'}`;
        }
    
    } catch (e) {
        console.debug('loadMapStats error:', e);
    }
}
// ============================================================
// ВЫБОР ИКОНКИ УЗЛА
// ============================================================

let selectedIconForNode = null;

function initIconPicker() {
    const picker = document.getElementById('editNodeIconPicker');
    if (!picker) return;
    
    picker.querySelectorAll('.icon-option').forEach(opt => {
        opt.addEventListener('click', () => {
            picker.querySelectorAll('.icon-option').forEach(o => o.classList.remove('selected'));
            opt.classList.add('selected');
            selectedIconForNode = opt.getAttribute('data-icon') || null;
        });
    });
}

async function saveNodeIcon(iconName) {
    if (!selectedNode) return;
    
    // Обновляем metadata узла
    const updatedNode = { ...selectedNode };
    if (!updatedNode.metadata) updatedNode.metadata = {};
    if (iconName) {
        updatedNode.metadata.icon = iconName;
    } else {
        delete updatedNode.metadata.icon;
    }
    
    const resp = await api(`/api/maps/${currentMap.id}/nodes/${selectedNode.id}/icon`, {
        method: 'PUT',
        body: JSON.stringify({ icon: iconName })
    });
    
    if (!resp || !resp.ok) {
        showNotification('Ошибка сохранения иконки', 'error');
        return false;
    }
    
    return true;
}

window.openLinkRootsModal = openLinkRootsModal;
window.linkRoots = linkRoots;
window.selectNode = selectNode;
window.selectMap = selectMap;
window.toggleNodeCollapse = toggleNodeCollapse;
window.closeModal = closeModal;
