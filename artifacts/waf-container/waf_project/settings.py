# =============================================================================
# БЛОК СИСТЕМНЫХ ИМПОРТОВ
# =============================================================================
import os
from pathlib import Path

# BASE_DIR — корневая директория проекта (artifacts/waf-container/)
# resolve() возвращает абсолютный путь, parent.parent — на два уровня вверх от settings.py
BASE_DIR = Path(__file__).resolve().parent.parent


# =============================================================================
# БЛОК БЕЗОПАСНОСТИ
# SECRET_KEY используется для подписи cookies, сессий, CSRF-токенов.
# В production ОБЯЗАТЕЛЬНО задавать через переменную окружения.
# =============================================================================
SECRET_KEY = os.environ.get(
    'DJANGO_SECRET_KEY',
    'dev-secret-key-change-in-production-xyz123'  # Дефолт только для разработки
)

# DEBUG=True — подробные страницы ошибок Django; в production ВСЕГДА False
DEBUG = os.environ.get('DEBUG', 'True') == 'True'

# ALLOWED_HOSTS — список допустимых хостов для HTTP-заголовка Host.
# '*' допустимо для разработки; в production указывать конкретные домены.
ALLOWED_HOSTS = ['*']


# =============================================================================
# БЛОК УСТАНОВЛЕННЫХ ПРИЛОЖЕНИЙ
# Порядок важен: whitenoise должен идти до staticfiles.
# =============================================================================
INSTALLED_APPS = [
    'django.contrib.admin',           # Административный интерфейс (/admin/)
    'django.contrib.auth',            # Система аутентификации пользователей
    'django.contrib.contenttypes',    # Фреймворк типов контента (нужен для admin)
    'django.contrib.sessions',        # Сессионная система
    'django.contrib.messages',        # Система flash-сообщений
    'whitenoise.runserver_nostatic',  # Отключает встроенный static-сервер Django
    'django.contrib.staticfiles',     # Управление статическими файлами
    'waf',                            # Основное WAF-приложение
]


# =============================================================================
# БЛОК ЦЕПОЧКИ MIDDLEWARE
# Порядок критически важен: каждый middleware оборачивает следующий.
# ForcedBrowsingProtectionMiddleware — наш WAF, ставим последним перед views.
# =============================================================================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',          # HTTPS-редиректы, заголовки безопасности
    'whitenoise.middleware.WhiteNoiseMiddleware',             # Раздача статики без nginx (dev)
    'django.contrib.sessions.middleware.SessionMiddleware',   # Поддержка сессий (admin)
    'django.middleware.common.CommonMiddleware',              # URL-нормализация (trailing slash)
    'django.contrib.auth.middleware.AuthenticationMiddleware',# Привязка user к request
    'django.contrib.messages.middleware.MessageMiddleware',   # Flash-сообщения
    'waf.middleware.ForcedBrowsingProtectionMiddleware',      # ← WAF: перехват всех запросов
]

# Корневой URL-конфигуратор — точка входа маршрутизации Django
ROOT_URLCONF = 'waf_project.urls'


# =============================================================================
# БЛОК КОНФИГУРАЦИИ ШАБЛОНИЗАТОРА
# APP_DIRS=True — Django ищет папку templates/ внутри каждого INSTALLED_APP.
# =============================================================================
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,   # Поиск в waf/templates/ автоматически
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',  # request доступен в шаблонах
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# Точка входа WSGI-сервера (gunicorn, uwsgi в production)
WSGI_APPLICATION = 'waf_project.wsgi.application'


# =============================================================================
# БЛОК КОНФИГУРАЦИИ БАЗЫ ДАННЫХ
# SQLite — встроенная файловая БД, достаточна для лабораторного проекта.
# Production: заменить на PostgreSQL/MySQL + Redis для in-memory счётчиков.
# =============================================================================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',   # Файл БД в корне проекта
    }
}


# =============================================================================
# БЛОК ЛОКАЛИЗАЦИИ И ВРЕМЕННЫ́Х ЗОН
# USE_TZ=True — все datetime в БД хранятся в UTC; отображение в TIME_ZONE.
# =============================================================================
LANGUAGE_CODE = 'ru-ru'          # Язык интерфейса Django Admin
TIME_ZONE = 'Europe/Moscow'      # Временна́я зона для отображения дат
USE_I18N = True                  # Включение интернационализации
USE_TZ = True                    # Хранение времени в UTC (рекомендуется)


# =============================================================================
# БЛОК СТАТИЧЕСКИХ ФАЙЛОВ
# whitenoise раздаёт static-файлы напрямую из Django без nginx.
# collectstatic собирает файлы из всех app в STATIC_ROOT.
# =============================================================================
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'   # Директория для collectstatic
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
# CompressedManifest — gzip-сжатие + версионирование (cache-busting)

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'   # Тип PK по умолчанию: BigInt


# =============================================================================
# БЛОК КОНФИГУРАЦИИ ДИРЕКТОРИИ ЛОГОВ
# mkdir(exist_ok=True) — создаём папку при первом запуске если не существует.
# =============================================================================
LOGS_DIR = BASE_DIR / 'logs'
LOGS_DIR.mkdir(exist_ok=True)   # Создание директории при отсутствии


# =============================================================================
# БЛОК КОНФИГУРАЦИИ СИСТЕМЫ ЛОГИРОВАНИЯ DJANGO
# Два логгера:
#   waf.security — события безопасности → консоль + JSON-файл
#   waf          — общие сообщения WAF  → только консоль
# =============================================================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,   # Не отключать стандартные логгеры Django

    # БЛОК ФОРМАТТЕРОВ
    'formatters': {
        'json': {
            '()': 'waf.logger.JsonFormatter',   # Наш кастомный JSON-форматтер
        },
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',   # Стиль форматирования: str.format()
        },
    },

    # БЛОК ОБРАБОТЧИКОВ ВЫВОДА
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',    # Вывод в stderr/stdout
            'formatter': 'verbose',
        },
        'json_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(LOGS_DIR / 'security_events.json'),
            'maxBytes': 10 * 1024 * 1024,   # Ротация при достижении 10 МБ
            'backupCount': 5,                # Хранить 5 архивных файлов
            'formatter': 'json',            # Форматирование в JSON
        },
    },

    # БЛОК НАСТРОЙКИ ЛОГГЕРОВ
    'loggers': {
        'waf.security': {
            'handlers': ['console', 'json_file'],  # События безопасности → в оба обработчика
            'level': 'INFO',
            'propagate': False,   # Не передавать в root-логгер (избегаем дублирования)
        },
        'waf': {
            'handlers': ['console'],   # Общие сообщения WAF — только консоль
            'level': 'INFO',
            'propagate': False,
        },
    },
}


# =============================================================================
# БЛОК КОНФИГУРАЦИИ WAF
# Путь к YAML-файлу конфигурации WAF.
# Может быть переопределён через переменную окружения WAF_CONFIG_PATH.
# =============================================================================
WAF_CONFIG_PATH = os.environ.get(
    'WAF_CONFIG_PATH',
    str(BASE_DIR / 'config' / 'waf_config.yaml')   # Путь по умолчанию
)
