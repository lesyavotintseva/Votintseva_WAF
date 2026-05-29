# =============================================================================
# БЛОК ИМПОРТА ЗАВИСИМОСТЕЙ
# =============================================================================
import json        # Сериализация событий в JSON-формат для ELK-стека
import logging     # Стандартный модуль логирования Python
import traceback   # Форматирование трассировки исключений
from datetime import datetime, timezone


# =============================================================================
# БЛОК JSON-ФОРМАТТЕРА ДЛЯ ELK-СОВМЕСТИМОГО ЛОГИРОВАНИЯ
# Преобразует стандартные LogRecord Python в структурированный JSON.
# Каждая строка лог-файла = один валидный JSON-объект (NDJSON-формат).
# Совместим с Logstash, Fluentd, Filebeat для импорта в ELK/OpenSearch.
# =============================================================================
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        """
        Форматирует запись лога в JSON-строку.
        Базовые поля + опциональные поля из record.extra + трассировка исключения.
        """
        # БЛОК ФОРМИРОВАНИЯ БАЗОВОЙ СТРУКТУРЫ СОБЫТИЯ
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),  # ISO 8601 с UTC-timezone
            'level': record.levelname,        # DEBUG / INFO / WARNING / ERROR / CRITICAL
            'logger': record.name,            # Имя логгера (waf.security, waf и т.д.)
            'message': record.getMessage(),   # Текст сообщения (args подставлены)
        }

        # БЛОК ДОБАВЛЕНИЯ РАСШИРЕННЫХ ПОЛЕЙ СОБЫТИЯ
        # Если вызывающий код передал extra={'extra': {...}}, разворачиваем внутрь
        if hasattr(record, 'extra'):
            log_entry.update(record.extra)   # Поля: event_type, source_ip, url, stats и т.д.

        # БЛОК ОБРАБОТКИ ИСКЛЮЧЕНИЙ
        # Добавляем полную трассировку стека при наличии исключения
        if record.exc_info:
            log_entry['exception'] = traceback.format_exception(*record.exc_info)

        # ensure_ascii=False — сохраняем кириллицу без экранирования (\uXXXX)
        return json.dumps(log_entry, ensure_ascii=False)


# =============================================================================
# БЛОК ИНИЦИАЛИЗАЦИИ ЛОГГЕРА БЕЗОПАСНОСТИ
# Логгер 'waf.security' настроен в settings.py на два обработчика:
#   1. ConsoleHandler  — вывод в терминал (для разработки)
#   2. RotatingFileHandler → logs/security_events.json (для ELK-интеграции)
# =============================================================================
security_logger = logging.getLogger('waf.security')


# =============================================================================
# БЛОК ПУБЛИЧНОГО API ЛОГИРОВАНИЯ
# Удобная функция-обёртка для записи событий безопасности.
# =============================================================================
def log_event(event_type: str, ip: str, url: str = '', **kwargs):
    """
    Записывает структурированное событие безопасности в JSON-лог.

    Параметры:
        event_type  — тип события (ip_blocked, attack_detected, ip_unblocked и т.д.)
        ip          — IP-адрес источника события
        url         — URL запроса (опционально)
        **kwargs    — дополнительные поля: reason, stats, expires_at и т.д.

    Пример записи в logs/security_events.json:
    {
      "timestamp": "2026-05-29T14:30:00.123456+00:00",
      "level": "INFO",
      "logger": "waf.security",
      "message": "ip_blocked: 185.220.101.45 -> /admin/",
      "event_type": "ip_blocked",
      "source_ip": "185.220.101.45",
      "url": "/admin/",
      "reason": "unique_url_limit",
      "stats": {"unique_urls": 52, "total_requests": 67, "error_rate": 78.5}
    }
    """
    # БЛОК СБОРКИ РАСШИРЕННОГО КОНТЕКСТА СОБЫТИЯ
    extra = {
        'event_type': event_type,   # Тип для фильтрации в Kibana/Grafana
        'source_ip': ip,            # IP для группировки инцидентов
        'url': url,                 # URL для анализа паттернов атаки
        **kwargs,                   # Произвольные дополнительные поля
    }

    # БЛОК ЗАПИСИ В ЛОГГЕР
    # extra={'extra': ...} — соглашение для JsonFormatter: поля верхнего уровня в JSON
    security_logger.info(
        f'{event_type}: {ip} -> {url}',   # Читаемое сообщение для консоли
        extra={'extra': extra}            # Структурированные данные для JSON-файла
    )
