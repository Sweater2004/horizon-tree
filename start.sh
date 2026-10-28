#!/bin/bash
# Horizon Tree — запуск сервера и открытие браузера

cd "$(dirname "$0")"
source venv/bin/activate

echo "▶ Запуск Horizon Tree..."

# Проверка, не занят ли порт
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️ Порт 8000 уже занят. Останавливаем старый процесс..."
    sudo fuser -k 8000/tcp
    sleep 1
fi

# Запускаем сервер в фоне
python app.py &
SERVER_PID=$!

# Ждём, пока сервер поднимется
echo "⏳ Ожидание сервера..."
for i in {1..20}; do
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        echo "✓ Сервер готов"
        break
    fi
    sleep 0.5
done

# Открываем браузер
echo "🌐 Открываем браузер..."
xdg-open http://localhost:8000 &

# Ждём завершения сервера (Ctrl+C для остановки)
echo "● Сервер работает. Ctrl+C для остановки."
wait $SERVER_PID
