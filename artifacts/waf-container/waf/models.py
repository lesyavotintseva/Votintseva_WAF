from django.db import models
from django.utils import timezone


class BlockedIP(models.Model):
    BLOCK_REASON_CHOICES = [
        ('unique_url_limit', 'Превышен лимит уникальных URL'),
        ('error_rate_limit', 'Превышена доля ошибок 404'),
        ('rps_limit', 'Превышен лимит запросов в секунду'),
        ('manual', 'Ручная блокировка'),
        ('whitelist_violation', 'Нарушение whitelist'),
    ]

    ip_address = models.GenericIPAddressField(unique=True, verbose_name='IP-адрес')
    blocked_at = models.DateTimeField(default=timezone.now, verbose_name='Заблокирован')
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name='Истекает')
    reason = models.CharField(
        max_length=50, choices=BLOCK_REASON_CHOICES,
        default='unique_url_limit', verbose_name='Причина'
    )
    unique_urls_count = models.IntegerField(default=0, verbose_name='Уникальных URL')
    total_requests = models.IntegerField(default=0, verbose_name='Всего запросов')
    error_404_count = models.IntegerField(default=0, verbose_name='Ошибок 404')
    is_active = models.BooleanField(default=True, verbose_name='Активна')
    notes = models.TextField(blank=True, verbose_name='Примечания')

    class Meta:
        verbose_name = 'Заблокированный IP'
        verbose_name_plural = 'Заблокированные IP'
        ordering = ['-blocked_at']

    def __str__(self):
        return f'{self.ip_address} ({"активна" if self.is_active else "снята"})'

    def is_expired(self):
        if self.expires_at and timezone.now() > self.expires_at:
            return True
        return False


class SecurityEvent(models.Model):
    EVENT_TYPE_CHOICES = [
        ('blocked_request', 'Заблокированный запрос'),
        ('ip_blocked', 'IP заблокирован'),
        ('ip_unblocked', 'IP разблокирован'),
        ('threshold_warning', 'Предупреждение о пороге'),
        ('attack_detected', 'Обнаружена атака'),
        ('scan_detected', 'Обнаружено сканирование'),
        ('allowed_request', 'Разрешённый запрос'),
    ]

    timestamp = models.DateTimeField(default=timezone.now, verbose_name='Время')
    event_type = models.CharField(max_length=30, choices=EVENT_TYPE_CHOICES, verbose_name='Тип события')
    source_ip = models.GenericIPAddressField(verbose_name='IP источника')
    url = models.TextField(verbose_name='URL')
    method = models.CharField(max_length=10, default='GET', verbose_name='Метод')
    status_code = models.IntegerField(null=True, blank=True, verbose_name='Код ответа')
    user_agent = models.TextField(blank=True, verbose_name='User-Agent')
    unique_urls_at_time = models.IntegerField(default=0, verbose_name='Уник. URL на момент события')
    requests_in_window = models.IntegerField(default=0, verbose_name='Запросов в окне')
    error_rate = models.FloatField(default=0.0, verbose_name='Доля ошибок')
    details = models.JSONField(default=dict, verbose_name='Детали')

    class Meta:
        verbose_name = 'Событие безопасности'
        verbose_name_plural = 'События безопасности'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['source_ip']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['event_type']),
        ]

    def __str__(self):
        return f'{self.event_type} — {self.source_ip} [{self.timestamp.strftime("%d.%m.%Y %H:%M:%S")}]'


class RequestLog(models.Model):
    timestamp = models.DateTimeField(default=timezone.now, verbose_name='Время')
    source_ip = models.GenericIPAddressField(verbose_name='IP источника')
    method = models.CharField(max_length=10, verbose_name='Метод')
    url = models.TextField(verbose_name='URL')
    status_code = models.IntegerField(null=True, blank=True, verbose_name='Код ответа')
    user_agent = models.TextField(blank=True, verbose_name='User-Agent')
    was_blocked = models.BooleanField(default=False, verbose_name='Заблокирован')
    response_time_ms = models.FloatField(null=True, blank=True, verbose_name='Время ответа (мс)')

    class Meta:
        verbose_name = 'Лог запроса'
        verbose_name_plural = 'Лог запросов'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['source_ip']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['was_blocked']),
        ]

    def __str__(self):
        status = 'BLOCKED' if self.was_blocked else str(self.status_code or '?')
        return f'{self.method} {self.url} [{status}] from {self.source_ip}'


class TrustedIP(models.Model):
    ip_or_subnet = models.CharField(max_length=50, unique=True, verbose_name='IP или подсеть')
    description = models.CharField(max_length=200, blank=True, verbose_name='Описание')
    added_at = models.DateTimeField(default=timezone.now, verbose_name='Добавлен')

    class Meta:
        verbose_name = 'Доверенный IP'
        verbose_name_plural = 'Доверенные IP'

    def __str__(self):
        return f'{self.ip_or_subnet} — {self.description}'
