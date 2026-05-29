# =============================================================================
# БЛОК ИМПОРТА ЗАВИСИМОСТЕЙ
# =============================================================================
from django.db import models
from django.utils import timezone


# =============================================================================
# БЛОК МОДЕЛИ ЗАБЛОКИРОВАННЫХ IP-АДРЕСОВ
# Таблица blocked_ip — хранит все активные и исторические блокировки.
# =============================================================================
class BlockedIP(models.Model):
    # Справочник причин блокировки — используется в дашборде и фильтрах
    BLOCK_REASON_CHOICES = [
        ('unique_url_limit', 'Превышен лимит уникальных URL'),
        ('error_rate_limit', 'Превышена доля ошибок 404'),
        ('rps_limit', 'Превышен лимит запросов в секунду'),
        ('manual', 'Ручная блокировка'),
        ('whitelist_violation', 'Нарушение whitelist'),
    ]

    # БЛОК ИДЕНТИФИКАЦИОННЫХ ПОЛЕЙ
    ip_address = models.GenericIPAddressField(
        unique=True,              # Один IP — одна запись (update_or_create при повторных атаках)
        verbose_name='IP-адрес'
    )

    # БЛОК ВРЕМЕННЫ́Х МЕТОК БЛОКИРОВКИ
    blocked_at = models.DateTimeField(
        default=timezone.now,     # Момент обнаружения атаки
        verbose_name='Заблокирован'
    )
    expires_at = models.DateTimeField(
        null=True, blank=True,    # NULL = постоянная блокировка
        verbose_name='Истекает'
    )

    # БЛОК ПРИЧИНЫ И КОНТЕКСТА БЛОКИРОВКИ
    reason = models.CharField(
        max_length=50,
        choices=BLOCK_REASON_CHOICES,
        default='unique_url_limit',
        verbose_name='Причина'
    )
    unique_urls_count = models.IntegerField(
        default=0,                # Число уникальных URL на момент блокировки (для отчётов)
        verbose_name='Уникальных URL'
    )
    total_requests = models.IntegerField(
        default=0,                # Всего запросов за окно на момент блокировки
        verbose_name='Всего запросов'
    )
    error_404_count = models.IntegerField(
        default=0,                # Число 404-ошибок на момент блокировки
        verbose_name='Ошибок 404'
    )

    # БЛОК УПРАВЛЕНИЯ СТАТУСОМ
    is_active = models.BooleanField(
        default=True,             # False = блокировка снята (разблокировка или истечение)
        verbose_name='Активна'
    )
    notes = models.TextField(blank=True, verbose_name='Примечания')

    class Meta:
        verbose_name = 'Заблокированный IP'
        verbose_name_plural = 'Заблокированные IP'
        ordering = ['-blocked_at']  # Новые блокировки — первыми

    def __str__(self):
        return f'{self.ip_address} ({"активна" if self.is_active else "снята"})'

    def is_expired(self):
        """Проверка истечения временно́й блокировки."""
        if self.expires_at and timezone.now() > self.expires_at:
            return True
        return False


# =============================================================================
# БЛОК МОДЕЛИ СОБЫТИЙ БЕЗОПАСНОСТИ
# Таблица security_event — журнал всех значимых событий WAF (аудит-трейл).
# =============================================================================
class SecurityEvent(models.Model):
    # Справочник типов событий — используется в фильтрах дашборда
    EVENT_TYPE_CHOICES = [
        ('blocked_request', 'Заблокированный запрос'),
        ('ip_blocked', 'IP заблокирован'),
        ('ip_unblocked', 'IP разблокирован'),
        ('threshold_warning', 'Предупреждение о пороге'),
        ('attack_detected', 'Обнаружена атака'),
        ('scan_detected', 'Обнаружено сканирование'),
        ('allowed_request', 'Разрешённый запрос'),
    ]

    # БЛОК ОСНОВНЫХ ДАННЫХ СОБЫТИЯ
    timestamp = models.DateTimeField(
        default=timezone.now,     # Точное время фиксации события
        verbose_name='Время'
    )
    event_type = models.CharField(
        max_length=30,
        choices=EVENT_TYPE_CHOICES,
        verbose_name='Тип события'
    )
    source_ip = models.GenericIPAddressField(verbose_name='IP источника')
    url = models.TextField(verbose_name='URL')          # Полный URL запроса
    method = models.CharField(
        max_length=10, default='GET', verbose_name='Метод'
    )
    status_code = models.IntegerField(
        null=True, blank=True,    # NULL если backend не вернул ответ
        verbose_name='Код ответа'
    )
    user_agent = models.TextField(blank=True, verbose_name='User-Agent')

    # БЛОК МЕТРИК НА МОМЕНТ СОБЫТИЯ (снимок состояния трекера)
    unique_urls_at_time = models.IntegerField(
        default=0,                # Уникальных URL накоплено к моменту события
        verbose_name='Уник. URL на момент события'
    )
    requests_in_window = models.IntegerField(
        default=0,                # Запросов в скользящем окне
        verbose_name='Запросов в окне'
    )
    error_rate = models.FloatField(
        default=0.0,              # Доля 404-ошибок на момент события (%)
        verbose_name='Доля ошибок'
    )
    details = models.JSONField(
        default=dict,             # Дополнительный контекст в JSON (причина, threshold и т.д.)
        verbose_name='Детали'
    )

    class Meta:
        verbose_name = 'Событие безопасности'
        verbose_name_plural = 'События безопасности'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['source_ip']),   # Быстрый поиск по IP
            models.Index(fields=['timestamp']),   # Быстрая фильтрация по времени
            models.Index(fields=['event_type']),  # Быстрая фильтрация по типу
        ]

    def __str__(self):
        return f'{self.event_type} — {self.source_ip} [{self.timestamp.strftime("%d.%m.%Y %H:%M:%S")}]'


# =============================================================================
# БЛОК МОДЕЛИ ЖУРНАЛА ЗАПРОСОВ
# Таблица request_log — полный лог входящих HTTP-запросов (сырые данные).
# Используется для построения графиков трафика на дашборде.
# =============================================================================
class RequestLog(models.Model):
    # БЛОК ДАННЫХ ЗАПРОСА
    timestamp = models.DateTimeField(default=timezone.now, verbose_name='Время')
    source_ip = models.GenericIPAddressField(verbose_name='IP источника')
    method = models.CharField(max_length=10, verbose_name='Метод')
    url = models.TextField(verbose_name='URL')
    status_code = models.IntegerField(
        null=True, blank=True,    # NULL если запрос был заблокирован до обращения к backend
        verbose_name='Код ответа'
    )
    user_agent = models.TextField(blank=True, verbose_name='User-Agent')

    # БЛОК РЕЗУЛЬТАТА ОБРАБОТКИ
    was_blocked = models.BooleanField(
        default=False,            # True = WAF заблокировал запрос (вернул 403)
        verbose_name='Заблокирован'
    )
    response_time_ms = models.FloatField(
        null=True, blank=True,    # Время ответа backend в миллисекундах
        verbose_name='Время ответа (мс)'
    )

    class Meta:
        verbose_name = 'Лог запроса'
        verbose_name_plural = 'Лог запросов'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['source_ip']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['was_blocked']),  # Индекс для агрегации блокировок
        ]

    def __str__(self):
        status = 'BLOCKED' if self.was_blocked else str(self.status_code or '?')
        return f'{self.method} {self.url} [{status}] from {self.source_ip}'


# =============================================================================
# БЛОК МОДЕЛИ ДОВЕРЕННЫХ IP (WHITELIST)
# Позволяет добавлять IP/подсети через Django Admin или интерфейс дашборда.
# =============================================================================
class TrustedIP(models.Model):
    ip_or_subnet = models.CharField(
        max_length=50, unique=True,
        verbose_name='IP или подсеть'   # Принимает как одиночный IP, так и CIDR (10.0.0.0/8)
    )
    description = models.CharField(max_length=200, blank=True, verbose_name='Описание')
    added_at = models.DateTimeField(default=timezone.now, verbose_name='Добавлен')

    class Meta:
        verbose_name = 'Доверенный IP'
        verbose_name_plural = 'Доверенные IP'

    def __str__(self):
        return f'{self.ip_or_subnet} — {self.description}'
