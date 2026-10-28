// ====== АДМИНКА ======
const API = '';
const token = localStorage.getItem('auth_token');
let currentUser = null;

if (!token) window.location.href = '/login';

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

async function loadUser() {
    const resp = await api('/api/auth/me');
    if (!resp) return;
    currentUser = await resp.json();
    document.getElementById('userBadge').textContent = 
        `${currentUser.username} · ${currentUser.role}`;
    if (currentUser.role !== 'admin') {
        document.getElementById('userBadge').textContent = 'Доступ запрещен (только админ)';
        document.querySelector('.admin-table').style.display = 'none';
        document.querySelector('.admin-form-row').style.display = 'none';
    }
}

async function loadUsers() {
    const resp = await api('/api/admin/users');
    if (!resp || !resp.ok) return;
    const data = await resp.json();
    const tbody = document.getElementById('usersList');
    if (!data.users || data.users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:40px; color: var(--md-on-surface-muted);">Нет пользователей</td></tr>';
        return;
    }
    tbody.innerHTML = data.users.map(u => {
        const isSelf = currentUser && u.id === currentUser.id;
        return `
            <tr>
                <td>
                    <b>${escapeHtml(u.username)}</b>
                    ${isSelf ? '<span class="self-mark"> (вы)</span>' : ''}
                </td>
                <td>
                    <span class="role-${u.role}">${u.role}</span>
                </td>
                <td>
                    <span class="${u.is_active ? 'status-active' : 'status-blocked'}">
                        ${u.is_active ? 'Активен' : 'Заблокирован'}
                    </span>
                </td>
                <td style="color: var(--md-on-surface-muted); font-size: 12px;">
                    ${u.last_login ? new Date(u.last_login).toLocaleString() : '—'}
                </td>
                <td>
                    ${!isSelf ? `
                        <button class="btn btn-small" onclick="openEditUserModal('${u.id}', '${escapeHtml(u.username)}', '${u.role}')">
                            Редактировать
                        </button>
                        <button class="btn btn-small" onclick="toggleUser('${u.id}', ${!u.is_active})">
                            ${u.is_active ? 'Заблокировать' : 'Разблокировать'}
                        </button>
                        <button class="btn btn-small btn-danger" onclick="deleteUser('${u.id}')">
                            Удалить
                        </button>
                    ` : '<span class="self-mark">—</span>'}
                </td>
            </tr>
        `;
    }).join('');
}

async function createUser() {
    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value;
    const role = document.getElementById('newRole').value;
    const msg = document.getElementById('createUserMessage');

    if (!username || !password || password.length < 6) {
        msg.className = 'admin-message show error';
        msg.textContent = 'Введите логин и пароль (минимум 6 символов)';
        return;
    }

    const resp = await api('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify({ username, password, role })
    });

    if (resp.ok) {
        msg.className = 'admin-message show success';
        msg.textContent = `Пользователь ${username} создан`;
        document.getElementById('newUsername').value = '';
        document.getElementById('newPassword').value = '';
        loadUsers();
    } else {
        const data = await resp.json();
        msg.className = 'admin-message show error';
        msg.textContent = data.detail || 'Ошибка';
    }
}

async function toggleUser(userId, newStatus) {
    if (!confirm(`Вы уверены?`)) return;
    const resp = await api(`/api/admin/users/${userId}`, {
        method: 'PUT',
        body: JSON.stringify({ is_active: newStatus })
    });
    if (resp.ok) loadUsers();
}

async function deleteUser(userId) {
    if (!confirm('Удалить пользователя? Это действие нельзя отменить!')) return;
    const resp = await api(`/api/admin/users/${userId}`, { method: 'DELETE' });
    if (resp.ok) loadUsers();
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function logout() {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_info');
    window.location.href = '/login';
}

async function init() {
    await loadUser();
    if (currentUser && currentUser.role === 'admin') {
        await loadUsers();
    }
}
// ====== РЕДАКТИРОВАНИЕ ПОЛЬЗОВАТЕЛЯ ======
let editingUserId = null;

function openEditUserModal(userId, username, role) {
    editingUserId = userId;
    document.getElementById('editUserTitle').textContent = `Редактировать: ${username}`;
    document.getElementById('editUsername').value = username;
    document.getElementById('editPassword').value = '';
    document.getElementById('editRole').value = role;
    document.getElementById('editUserModal').classList.add('show');
}

async function saveEditedUser() {
    if (!editingUserId) return;

    const newUsername = document.getElementById('editUsername').value.trim();
    const newPassword = document.getElementById('editPassword').value;
    const newRole = document.getElementById('editRole').value;

    if (!newUsername) {
        alert('Введите логин');
        return;
    }
    if (newPassword && newPassword.length < 6) {
        alert('Пароль должен быть минимум 6 символов');
        return;
    }

    const body = {};
    if (newUsername) body.username = newUsername;
    if (newPassword) body.password = newPassword;
    if (newRole) body.role = newRole;

    const btn = document.getElementById('saveEditedUserBtn');
    btn.disabled = true;

    const resp = await api(`/api/admin/users/${editingUserId}`, {
        method: 'PUT',
        body: JSON.stringify(body)
    });

    btn.disabled = false;

    if (resp.ok) {
        closeModal('editUserModal');
        loadUsers();
        alert('Пользователь обновлён');
    } else {
        const data = await resp.json();
        alert(data.detail || 'Ошибка');
    }
}

function closeModal(id) {
    document.getElementById(id).classList.remove('show');
}

// Инициализация — после всех функций
init();
