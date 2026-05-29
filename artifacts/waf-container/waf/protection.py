# =============================================================================
# БЛОК ИМПОРТА И ИНИЦИАЛИЗАЦИИ ЗАВИСИМОСТЕЙ
# =============================================================================
import threading    # Потокобезопасность счётчиков при параллельных запросах
import time         # Временны́е метки для скользящего окна
import ipaddress    # Разбор IP-адресов и CIDR-подсетей (whitelist)
from collections import defaultdict, deque  # deque — эффективная очередь с ограничением
from datetime import datetime, timezone     # Дата/время с поддержкой часового пояса
from typing import Optional
import logging
import yaml         # Чтение конфигурации из waf_config.yaml
import os

logger = logging.getLogger('waf')


# =============================================================================
# БЛОК ОТСЛЕЖИВАНИЯ АКТИВНОСТИ ОДНОГО IP (ТРЕКЕР)
# Хранит временны́е ряды запросов в памяти для скользящего окна.
# =============================================================================
class IPTracker:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds   # Размер скользящего окна (секунды)
        self.lock = threading.Lock()           # Мьютекс — защита от гонки потоков

        # deque — двусторонняя очередь: старые записи удаляются с левого конца
        self.timestamps: deque = deque()         # Временны́е метки всех запросов (не используется напрямую)
        self.unique_urls: set = set()            # Множество уникальных URL от данного IP
        self.error_404_times: deque = deque()    # Временны́е метки 404-ответов
        self.all_request_times: deque = deque()  # Временны́е метки всех запросов

    def add_request(self, url: str, status_code: Optional[int], ts: float):
        """
        БЛОК ЗАПИСИ ЗАПРОСА В ТРЕКЕР
        Добавляет запрос в скользящее окно и удаляет устаревшие записи.
        """
        with self.lock:  # Захват мьютекса — атомарная операция
            cutoff = ts - self.window_seconds  # Граница окна: всё старее — выбрасываем

            # Очистка устаревших записей из начала очереди (самые старые — слева)
            while self.all_request_times and self.all_request_times[0] < cutoff:
                self.all_request_times.popleft()   # O(1) удаление из начала
            while self.error_404_times and self.error_404_times[0] < cutoff:
                self.error_404_times.popleft()

            # Добавление нового запроса в конец очереди
            self.all_request_times.append(ts)
            if status_code == 404:
                self.error_404_times.append(ts)   # Фиксируем 404 отдельно для rate-анализа

            # set.add() автоматически игнорирует дубликаты — считаем только уникальные URL
            self.unique_urls.add(url)

    def get_stats(self, ts: float) -> dict:
        """
        БЛОК ВЫЧИСЛЕНИЯ ТЕКУЩЕЙ СТАТИСТИКИ
        Возвращает актуальные метрики для оценки угрозы.
        """
        with self.lock:
            cutoff = ts - self.window_seconds
            # Подсчёт запросов, попавших в текущее окно
            recent_total = sum(1 for t in self.all_request_times if t >= cutoff)
            recent_404 = sum(1 for t in self.error_404_times if t >= cutoff)
            # Доля 404-ответов: ключевой признак атаки форсированного браузинга
            error_rate = (recent_404 / recent_total * 100) if recent_total > 0 else 0.0
            return {
                'unique_urls': len(self.unique_urls),       # Число уникальных URL — главный индикатор
                'total_requests': recent_total,             # Запросов за окно
                'error_404_count': recent_404,              # Ошибок 404 за окно
                'error_rate': round(error_rate, 1),         # Доля 404 в процентах
            }

    def reset(self):
        """Сброс счётчиков при ручной разблокировке IP."""
        with self.lock:
            self.unique_urls.clear()
            self.all_request_times.clear()
            self.error_404_times.clear()


# =============================================================================
# БЛОК КОНФИГУРАЦИИ ПО УМОЛЧАНИЮ
# Используется если waf_config.yaml не найден или не читается.
# =============================================================================
DEFAULT_CONFIG = {
    'backend_url': os.environ.get('BACKEND_URL', ''),  # URL защищаемого приложения
    'window_seconds': 60,          # Размер скользящего окна в секундах
    'thresholds': {
        'unique_urls': 50,             # Макс. уникальных URL за окно (главный порог)
        'error_rate_percent': 70.0,    # Макс. доля 404-ответов (%)
        'min_requests_for_rate': 10,   # Мин. запросов для проверки rate-порога
        'rps': 30,                     # Макс. запросов в секунду
    },
    'block_duration_seconds': 3600,  # Длительность блокировки (1 час)
    'mode': 'block',                 # Режим: block / monitoring / disabled
    'whitelist': ['127.0.0.1', '::1'],            # Доверенные IP (никогда не блокируются)
    'excluded_paths': ['/waf/', '/admin/', '/static/', '/favicon.ico'],
    'response_codes': {'blocked': 403},           # HTTP-код для заблокированных запросов
}


# =============================================================================
# БЛОК ДВИЖКА ЗАЩИТЫ (SINGLETON)
# Единственный экземпляр на весь процесс Django — хранит состояние всех IP.
# Паттерн Singleton обеспечивает общую память между воркерами одного процесса.
# =============================================================================
class ProtectionEngine:
    _instance = None
    _lock = threading.Lock()  # Блокировка для потокобезопасного создания singleton

    @classmethod
    def get_instance(cls):
        """Потокобезопасное создание единственного экземпляра (double-checked locking)."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:   # Повторная проверка после захвата блокировки
                    cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.config = self._load_config()             # Загрузка конфига из YAML
        self._trackers: dict[str, IPTracker] = {}     # Словарь трекеров: IP → IPTracker
        self._trackers_lock = threading.Lock()        # Мьютекс доступа к словарю трекеров
        self._manual_blocks: dict[str, datetime] = {} # Ручные блокировки (in-memory)
        self._manual_blocks_lock = threading.Lock()

        # Фоновый поток очистки устаревших трекеров (daemon = завершится с процессом)
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        logger.info('ProtectionEngine инициализирован, конфиг: %s', self.config)

    # -------------------------------------------------------------------------
    # БЛОК ЗАГРУЗКИ КОНФИГУРАЦИИ
    # -------------------------------------------------------------------------
    def _load_config(self) -> dict:
        """
        Читает waf_config.yaml и объединяет с DEFAULT_CONFIG.
        При ошибке чтения возвращает конфиг по умолчанию (fail-safe).
        """
        from django.conf import settings
        cfg_path = getattr(settings, 'WAF_CONFIG_PATH', '')
        config = DEFAULT_CONFIG.copy()
        if cfg_path and os.path.exists(cfg_path):
            try:
                with open(cfg_path, 'r', encoding='utf-8') as f:
                    file_cfg = yaml.safe_load(f) or {}  # safe_load — без выполнения кода из YAML
                config.update(file_cfg)
                if 'thresholds' in file_cfg:
                    # Слияние вложенного словаря thresholds с дефолтными значениями
                    config['thresholds'] = {**DEFAULT_CONFIG['thresholds'], **file_cfg['thresholds']}
                logger.info('Конфиг загружен из %s', cfg_path)
            except Exception as e:
                logger.error('Ошибка загрузки конфига: %s', e)
        return config

    def reload_config(self):
        """Горячая перезагрузка конфига без перезапуска сервера."""
        self.config = self._load_config()

    # -------------------------------------------------------------------------
    # БЛОК ВСПОМОГАТЕЛЬНЫХ ПРОВЕРОК
    # -------------------------------------------------------------------------
    def _get_tracker(self, ip: str) -> IPTracker:
        """Возвращает трекер для IP, создавая новый если не существует."""
        with self._trackers_lock:
            if ip not in self._trackers:
                self._trackers[ip] = IPTracker(self.config['window_seconds'])
            return self._trackers[ip]

    def _is_whitelisted(self, ip: str) -> bool:
        """
        Проверяет IP против списка доверенных адресов и подсетей.
        Поддерживает как одиночные IP, так и CIDR-нотацию (192.168.0.0/16).
        """
        for entry in self.config.get('whitelist', []):
            try:
                if '/' in entry:
                    # Проверка вхождения IP в подсеть (CIDR)
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                        return True
                elif ip == entry:
                    return True
            except ValueError:
                pass
        return False

    def _is_excluded_path(self, path: str) -> bool:
        """Пути /waf/, /admin/, /static/ исключены из WAF-анализа."""
        for excluded in self.config.get('excluded_paths', []):
            if path.startswith(excluded):
                return True
        return False

    # -------------------------------------------------------------------------
    # БЛОК ПРОВЕРКИ СТАТУСА БЛОКИРОВКИ
    # -------------------------------------------------------------------------
    def is_blocked(self, ip: str) -> bool:
        """
        Главная проверка: заблокирован ли данный IP.
        Порядок: whitelist → in-memory блок → БД (BlockedIP).
        """
        if self._is_whitelisted(ip):
            return False  # Whitelist имеет наивысший приоритет

        # Проверка ручных блокировок в памяти (быстрее, чем запрос к БД)
        with self._manual_blocks_lock:
            if ip in self._manual_blocks:
                expires = self._manual_blocks[ip]
                if expires is None or datetime.now(timezone.utc) < expires:
                    return True
                else:
                    del self._manual_blocks[ip]  # Истёкшая блокировка — удаляем

        # Проверка персистентных блокировок в БД (SQLite)
        try:
            from waf.models import BlockedIP
            from django.utils import timezone as dj_tz
            block = BlockedIP.objects.filter(ip_address=ip, is_active=True).first()
            if block:
                if block.expires_at and dj_tz.now() > block.expires_at:
                    block.is_active = False
                    block.save(update_fields=['is_active'])  # Деактивация истёкшей блокировки
                    return False
                return True
        except Exception:
            pass
        return False

    # -------------------------------------------------------------------------
    # БЛОК АНАЛИЗА И ПРИНЯТИЯ РЕШЕНИЙ (ЯДРО WAF)
    # Основная логика обнаружения атаки: обновляет трекер, проверяет пороги.
    # -------------------------------------------------------------------------
    def check_and_record(self, ip: str, url: str, path: str, method: str,
                          status_code: Optional[int], user_agent: str = '') -> dict:
        """
        Главный метод движка: анализирует один запрос и возвращает решение.
        Возвращаемые действия: 'allow', 'whitelist', 'block', 'monitor', 'warn'.
        """
        result = {'action': 'allow', 'reason': None, 'stats': {}}

        if self._is_whitelisted(ip):
            result['action'] = 'whitelist'
            return result

        if self._is_excluded_path(path):
            return result  # Системные пути пропускаем без анализа

        if self.is_blocked(ip):
            result['action'] = 'block'
            result['reason'] = 'ip_already_blocked'
            self._record_blocked_event(ip, url, method, user_agent, status_code, 'ip_already_blocked')
            return result

        # Обновление трекера: добавление текущего запроса в скользящее окно
        tracker = self._get_tracker(ip)
        ts = time.time()
        tracker.add_request(url, status_code, ts)
        stats = tracker.get_stats(ts)    # Текущие метрики данного IP
        result['stats'] = stats

        # Чтение порогов из конфига
        thresholds = self.config.get('thresholds', {})
        unique_limit = thresholds.get('unique_urls', 50)
        error_rate_limit = thresholds.get('error_rate_percent', 70.0)
        min_requests = thresholds.get('min_requests_for_rate', 10)
        rps_limit = thresholds.get('rps', 30)

        # Вычисление RPS = кол-во запросов / размер окна
        window = self.config.get('window_seconds', 60)
        rps = stats['total_requests'] / window if window > 0 else 0

        # БЛОК ПРОВЕРКИ ПОРОГОВ: три независимых критерия атаки
        violation_reason = None
        if stats['unique_urls'] >= unique_limit:
            # Критерий 1: слишком много уникальных URL — признак перебора словарём
            violation_reason = 'unique_url_limit'
        elif stats['total_requests'] >= min_requests and stats['error_rate'] >= error_rate_limit:
            # Критерий 2: высокая доля 404 — признак сканирования несуществующих ресурсов
            violation_reason = 'error_rate_limit'
        elif rps >= rps_limit:
            # Критерий 3: слишком высокая частота запросов — признак автоматизированного инструмента
            violation_reason = 'rps_limit'

        if violation_reason:
            mode = self.config.get('mode', 'block')
            if mode in ('block', 'monitoring'):
                self._block_ip(ip, violation_reason, stats)  # Запись блокировки в БД
                if mode == 'block':
                    result['action'] = 'block'      # Режим block — запрос отклоняется
                else:
                    result['action'] = 'monitor'    # Режим monitoring — только логируем
                result['reason'] = violation_reason
            self._record_attack_event(ip, url, method, user_agent, status_code, violation_reason, stats)
        elif stats['unique_urls'] >= int(unique_limit * 0.7):
            # Предупреждение при достижении 70% порога — ранний сигнал
            result['action'] = 'warn'
            result['reason'] = 'approaching_limit'
            self._record_warning_event(ip, url, method, user_agent, stats)

        return result

    # -------------------------------------------------------------------------
    # БЛОК ЗАПИСИ БЛОКИРОВКИ В БАЗУ ДАННЫХ
    # -------------------------------------------------------------------------
    def _block_ip(self, ip: str, reason: str, stats: dict):
        """
        Создаёт или обновляет запись BlockedIP в SQLite.
        update_or_create — атомарная операция: создаёт если нет, обновляет если есть.
        """
        from waf.models import BlockedIP
        from django.utils import timezone as dj_tz
        import datetime as dt

        duration = self.config.get('block_duration_seconds', 3600)
        expires = dj_tz.now() + dt.timedelta(seconds=duration) if duration > 0 else None
        try:
            BlockedIP.objects.update_or_create(
                ip_address=ip,
                defaults={
                    'is_active': True,
                    'reason': reason,
                    'blocked_at': dj_tz.now(),
                    'expires_at': expires,
                    'unique_urls_count': stats.get('unique_urls', 0),
                    'total_requests': stats.get('total_requests', 0),
                    'error_404_count': stats.get('error_404_count', 0),
                }
            )
            from waf.logger import log_event
            log_event('ip_blocked', ip, reason=reason, stats=stats,
                      expires_at=expires.isoformat() if expires else None)
        except Exception as e:
            logger.error('Ошибка блокировки IP %s: %s', ip, e)

    # -------------------------------------------------------------------------
    # БЛОК ЗАПИСИ СОБЫТИЙ БЕЗОПАСНОСТИ
    # -------------------------------------------------------------------------
    def _record_blocked_event(self, ip, url, method, user_agent, status_code, reason):
        """Событие: запрос от уже заблокированного IP."""
        self._save_event('blocked_request', ip, url, method, user_agent, status_code,
                         {'reason': reason})

    def _record_attack_event(self, ip, url, method, user_agent, status_code, reason, stats):
        """Событие: обнаружена атака, порог превышен."""
        self._save_event('attack_detected', ip, url, method, user_agent, status_code, {
            'reason': reason,
            'unique_urls': stats.get('unique_urls'),
            'total_requests': stats.get('total_requests'),
            'error_rate': stats.get('error_rate'),
        }, stats)
        from waf.logger import log_event
        log_event('attack_detected', ip, url=url, method=method, reason=reason, stats=stats)

    def _record_warning_event(self, ip, url, method, user_agent, stats):
        """Событие: IP приближается к порогу (70% от лимита уникальных URL)."""
        self._save_event('threshold_warning', ip, url, method, user_agent, None,
                         {'unique_urls': stats.get('unique_urls')}, stats)

    def _save_event(self, event_type, ip, url, method, user_agent,
                    status_code, details, stats=None):
        """
        Универсальный метод записи события в таблицу SecurityEvent (SQLite).
        Вызывается асинхронно из потока запроса — ошибки не прерывают обработку.
        """
        try:
            from waf.models import SecurityEvent
            stats = stats or {}
            SecurityEvent.objects.create(
                event_type=event_type,
                source_ip=ip,
                url=url,
                method=method,
                status_code=status_code,
                user_agent=user_agent,
                unique_urls_at_time=stats.get('unique_urls', 0),
                requests_in_window=stats.get('total_requests', 0),
                error_rate=stats.get('error_rate', 0.0),
                details=details,
            )
        except Exception as e:
            logger.error('Ошибка записи события: %s', e)

    # -------------------------------------------------------------------------
    # БЛОК УПРАВЛЕНИЯ БЛОКИРОВКАМИ (API-методы)
    # -------------------------------------------------------------------------
    def manual_block(self, ip: str, duration_seconds: int = 3600, reason: str = 'manual'):
        """Ручная блокировка IP через дашборд или API."""
        stats = {}
        tracker = self._trackers.get(ip)
        if tracker:
            stats = tracker.get_stats(time.time())
        self._block_ip(ip, reason, stats)

    def manual_unblock(self, ip: str):
        """Ручная разблокировка: деактивирует запись в БД и сбрасывает трекер."""
        try:
            from waf.models import BlockedIP
            BlockedIP.objects.filter(ip_address=ip).update(is_active=False)
            with self._manual_blocks_lock:
                self._manual_blocks.pop(ip, None)   # Удаляем из in-memory блокировок
            tracker = self._trackers.get(ip)
            if tracker:
                tracker.reset()  # Обнуляем счётчики — IP начинает с чистого листа
            from waf.logger import log_event
            log_event('ip_unblocked', ip)
        except Exception as e:
            logger.error('Ошибка разблокировки IP %s: %s', ip, e)

    def get_ip_stats(self, ip: str) -> dict:
        """Возвращает текущую статистику конкретного IP для API."""
        tracker = self._trackers.get(ip)
        if tracker:
            return tracker.get_stats(time.time())
        return {}

    def get_all_trackers_summary(self) -> list:
        """Сводка по всем активным IP-трекерам для live-мониторинга на дашборде."""
        ts = time.time()
        result = []
        with self._trackers_lock:
            for ip, tracker in self._trackers.items():
                stats = tracker.get_stats(ts)
                if stats['total_requests'] > 0:
                    result.append({'ip': ip, **stats})
        return sorted(result, key=lambda x: x['unique_urls'], reverse=True)

    # -------------------------------------------------------------------------
    # БЛОК ФОНОВОЙ ОЧИСТКИ УСТАРЕВШИХ ДАННЫХ
    # -------------------------------------------------------------------------
    def _cleanup_loop(self):
        """
        Фоновый поток (daemon): каждые 5 минут удаляет неактивные трекеры
        и деактивирует истёкшие блокировки в БД.
        Предотвращает утечку памяти при большом числе уникальных IP.
        """
        while True:
            time.sleep(300)  # Интервал очистки: 5 минут
            try:
                ts = time.time()
                window = self.config.get('window_seconds', 60)
                cutoff = ts - window * 3  # Трекеры без активности за 3 окна — удалить

                with self._trackers_lock:
                    inactive = [
                        ip for ip, tracker in self._trackers.items()
                        if not tracker.all_request_times
                        or tracker.all_request_times[-1] < cutoff
                    ]
                    for ip in inactive:
                        del self._trackers[ip]

                # Деактивация истёкших блокировок в БД
                try:
                    from waf.models import BlockedIP
                    from django.utils import timezone as dj_tz
                    BlockedIP.objects.filter(
                        is_active=True, expires_at__lt=dj_tz.now()
                    ).update(is_active=False)
                except Exception:
                    pass
            except Exception as e:
                logger.error('Ошибка очистки: %s', e)
