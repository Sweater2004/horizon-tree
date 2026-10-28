// ====== ЛОГИН ======
const API_BASE = '';

async function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('errorMessage');
    const loginBtn = document.getElementById('loginBtn');

    errorEl.className = 'login-error';
    errorEl.textContent = '';

    if (!username || !password) {
        errorEl.textContent = 'Введите логин и пароль';
        errorEl.className = 'login-error show';
        return;
    }

    loginBtn.classList.add('loading');
    loginBtn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('auth_token', data.access_token);
            localStorage.setItem('user_info', JSON.stringify(data.user));
            window.location.href = '/';
        } else {
            errorEl.textContent = data.detail || 'Ошибка авторизации';
            errorEl.className = 'login-error show';
        }
    } catch (err) {
        errorEl.textContent = 'Ошибка подключения к серверу';
        errorEl.className = 'login-error show';
        console.error(err);
    } finally {
        loginBtn.classList.remove('loading');
        loginBtn.disabled = false;
    }
}

// Enter в поле пароля — отправить форму
document.getElementById('password').addEventListener('keypress', e => {
    if (e.key === 'Enter') login();
});

// Enter в поле логина — фокус на пароль
document.getElementById('username').addEventListener('keypress', e => {
    if (e.key === 'Enter') document.getElementById('password').focus();
});

// Если уже есть токен — проверим его валидность
(async () => {
    const token = localStorage.getItem('auth_token');
    if (!token) return;
    try {
        const resp = await fetch('/api/auth/me', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (resp.ok) {
            window.location.href = '/';
        } else {
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_info');
        }
    } catch (e) {
        // Сеть недоступна — не редиректим
    }
})();
