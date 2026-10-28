"""
Horizon Tree — GUI (PyQt5).
- Управление сервером.
- Настройка адреса.
- Два поля: логи (stdout) и ошибки (stderr).
"""
import os
import sys
import json
import webbrowser
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QGroupBox,
    QMessageBox, QFormLayout, QSpinBox, QSplitter
)
from PyQt5.QtCore import Qt, QTimer, QProcess, QProcessEnvironment


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON = os.path.join(BASE_DIR, "venv", "bin", "python")
APP_PY = os.path.join(BASE_DIR, "app.py")
CONFIG_FILE = os.path.join(BASE_DIR, "gui_config.json")


DEFAULT_CONFIG = {"host": "127.0.0.1", "port": 8000}


class HorizonTreeGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.process = None
        self.config = self._load_config()

        self.setWindowTitle("Horizon Tree v5.0 — Launcher")
        self.setGeometry(100, 100, 1300, 800)
        self.setMinimumSize(1100, 700)

        self._apply_light_theme()
        self._build_ui()

        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._check_server_status)
        self.status_timer.start(2000)

    def _apply_light_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #f5f5f7; color: #1a1a1f; font-family: 'Segoe UI', sans-serif; }
            QGroupBox { border: 1px solid #e0e0e5; border-radius: 8px; margin-top: 12px; padding-top: 12px; font-weight: 600; background-color: #ffffff; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #6200ee; }
            QLabel { color: #1a1a1f; }
            QLineEdit, QSpinBox { background-color: #ffffff; border: 1px solid #d0d0d5; border-radius: 6px; padding: 8px; color: #1a1a1f; font-size: 13px; }
            QLineEdit:focus, QSpinBox:focus { border: 1px solid #6200ee; }
            QPushButton { background-color: #e8e8ed; border: none; border-radius: 6px; padding: 10px 20px; color: #1a1a1f; font-size: 13px; font-weight: 600; }
            QPushButton:hover { background-color: #d8d8dd; }
            QPushButton:disabled { background-color: #f0f0f5; color: #9a9aa5; }
            QPushButton#primary { background-color: #6200ee; color: #ffffff; }
            QPushButton#primary:hover { background-color: #7c3aed; }
            QPushButton#danger { background-color: #dc3545; color: #ffffff; }
            QPushButton#danger:hover { background-color: #e74c5b; }
            QPushButton#success { background-color: #00c853; color: #ffffff; }
            QPushButton#success:hover { background-color: #00e676; }
            QTextEdit { background-color: #1e1e24; border: 1px solid #333; border-radius: 6px; padding: 8px; color: #d4d4d4; font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; }
        """)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Заголовок
        title = QLabel("Horizon Tree v5.0")
        title.setStyleSheet("font-size: 24px; font-weight: 700; color: #6200ee;")
        layout.addWidget(title)

        # Статус
        self.status_label = QLabel("⏹ Сервер остановлен")
        self.status_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #dc3545; padding: 4px;")
        layout.addWidget(self.status_label)

        # Настройки
        config_group = QGroupBox("Настройки сервера")
        config_layout = QFormLayout(config_group)
        config_layout.setSpacing(8)

        self.host_input = QLineEdit(self.config["host"])
        config_layout.addRow("Хост:", self.host_input)

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(self.config["port"])
        config_layout.addRow("Порт:", self.port_input)

        self.url_label = QLabel(self._get_url())
        self.url_label.setStyleSheet("color: #00c853; font-family: monospace;")
        self.url_label.setCursor(Qt.PointingHandCursor)
        self.url_label.mousePressEvent = lambda e: self._open_browser()
        config_layout.addRow("Адрес:", self.url_label)

        self.host_input.textChanged.connect(self._update_url_label)
        self.port_input.valueChanged.connect(self._update_url_label)

        layout.addWidget(config_group)

        # Кнопки
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self.btn_start = QPushButton("▶ Запустить")
        self.btn_start.setObjectName("primary")
        self.btn_start.clicked.connect(self._start_server)
        btn_layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹ Остановить")
        self.btn_stop.setObjectName("danger")
        self.btn_stop.clicked.connect(self._stop_server)
        self.btn_stop.setEnabled(False)
        btn_layout.addWidget(self.btn_stop)

        self.btn_browser = QPushButton("🌐 Браузер")
        self.btn_browser.setObjectName("success")
        self.btn_browser.clicked.connect(self._open_browser)
        btn_layout.addWidget(self.btn_browser)

        btn_save = QPushButton("💾 Сохранить")
        btn_save.clicked.connect(self._save_config)
        btn_layout.addWidget(btn_save)

        btn_clear_logs = QPushButton("🗑 Очистить логи")
        btn_clear_logs.clicked.connect(self._clear_logs)
        btn_layout.addWidget(btn_clear_logs)

        layout.addLayout(btn_layout)

        # Одно окно с логами
        log_group = QGroupBox("📋 Логи")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e24;
                border: 1px solid #333;
                border-radius: 6px;
                padding: 12px;
                color: #d4d4d4;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 14px;
                line-height: 1.5;
            }
        """)
        log_layout.addWidget(self.log_text)
        layout.addWidget(log_group, stretch=1)

        # Инициализация
        self._log_info(f"venv: {PYTHON}")
        self._log_info(f"app.py: {APP_PY}")
        if not os.path.exists(PYTHON):
            self._log_error(f"⚠️ venv не найден: {PYTHON}")
            self.btn_start.setEnabled(False)

    def _get_url(self):
        return f"http://{self.host_input.text()}:{self.port_input.value()}"

    def _update_url_label(self):
        self.url_label.setText(self._get_url())

    def _log_info(self, message):
        ts = datetime.now().strftime("%H:%M:%S")
        html = f'<span style="color: #6b6b75;">[{ts}]</span> <span style="color: #d4d4d4;">{message}</span>'
        self.log_text.append(html)

    def _log_info(self, message, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        colors = {
            "info": "#d4d4d4",
            "success": "#00c853",
            "error": "#ff6b6b",
            "warning": "#ff9800",
        }
        color = colors.get(level, "#d4d4d4")
        html = f'<span style="color: #6b6b75;">[{ts}]</span> <span style="color: {color};">{message}</span>'
        self.log_text.append(html)

    def _clear_logs(self):
        self.log_text.clear()

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    return {**DEFAULT_CONFIG, **json.load(f)}
            except Exception:
                pass
        return DEFAULT_CONFIG.copy()

    def _save_config(self):
        self.config = {"host": self.host_input.text(), "port": self.port_input.value()}
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
            self._log_info(f"✓ Настройки сохранены: {self._get_url()}")
        except Exception as e:
            self._log_error(f"✗ Ошибка сохранения: {e}")

    def _check_server_status(self):
        if self.process and self.process.state() == QProcess.Running:
            self.status_label.setText("● Сервер работает")
            self.status_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #00c853; padding: 4px;")
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
        else:
            self.status_label.setText("⏹ Сервер остановлен")
            self.status_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #dc3545; padding: 4px;")
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)

    def _start_server(self):
        if self.process and self.process.state() == QProcess.Running:
            self._log_error("⚠️ Сервер уже запущен")
            return

        if not os.path.exists(APP_PY):
            self._log_error(f"✗ app.py не найден: {APP_PY}")
            return

        self._save_config()

        host = self.host_input.text()
        port = self.port_input.value()

        self._log_info(f"▶ Запуск сервера на {host}:{port}...")

        self.process = QProcess(self)
        self.process.setWorkingDirectory(BASE_DIR)

        env = QProcessEnvironment.systemEnvironment()
        env.insert("HORIZON_HOST", host)
        env.insert("HORIZON_PORT", str(port))
        env.insert("PYTHONUNBUFFERED", "1")
        self.process.setProcessEnvironment(env)

        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._server_finished)
        self.process.errorOccurred.connect(self._server_error)

        self.process.start(PYTHON, [APP_PY])
        self._log_info("⏳ Ожидание запуска...")

    def _read_stdout(self):
        data = self.process.readAllStandardOutput().data().decode("utf-8", errors="replace")
        for line in data.splitlines():
            if line.strip():
                self._log_info(line)

    def _read_stderr(self):
        data = self.process.readAllStandardError().data().decode("utf-8", errors="replace")
        for line in data.splitlines():
            if line.strip():
                self._log_info(line, "error")  # ← красным

    def _server_finished(self, exit_code, exit_status):
        self._log_info(f"⏹ Сервер остановлен (код {exit_code})")
        self.process = None

    def _server_error(self, error):
        self._log_error(f"✗ Ошибка сервера: {error}")

    def _stop_server(self):
        if not self.process or self.process.state() != QProcess.Running:
            return
        self._log_info("⏹ Остановка сервера...")
        self.process.terminate()
        if not self.process.waitForFinished(5000):
            self.process.kill()
        self.process = None

    def _open_browser(self):
        webbrowser.open(self._get_url())
        self._log_info(f"🌐 Открыт браузер: {self._get_url()}")

    def closeEvent(self, event):
        if self.process and self.process.state() == QProcess.Running:
            reply = QMessageBox.question(
                self, "Выход", "Сервер работает. Остановить и выйти?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self._stop_server()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Horizon Tree")
    window = HorizonTreeGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()