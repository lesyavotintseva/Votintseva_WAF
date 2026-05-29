import threading
import time
import ipaddress
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional
import logging
import yaml
import os

logger = logging.getLogger('waf')


class IPTracker:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.lock = threading.Lock()
        self.timestamps: deque = deque()
        self.unique_urls: set = set()
        self.error_404_times: deque = deque()
        self.all_request_times: deque = deque()

    def add_request(self, url: str, status_code: Optional[int], ts: float):
        with self.lock:
            cutoff = ts - self.window_seconds
            while self.all_request_times and self.all_request_times[0] < cutoff:
                self.all_request_times.popleft()
            while self.error_404_times and self.error_404_times[0] < cutoff:
                self.error_404_times.popleft()
            self.all_request_times.append(ts)
            if status_code == 404:
                self.error_404_times.append(ts)
            self.unique_urls.add(url)

    def get_stats(self, ts: float):
        with self.lock:
            cutoff = ts - self.window_seconds
            recent_total = sum(1 for t in self.all_request_times if t >= cutoff)
            recent_404 = sum(1 for t in self.error_404_times if t >= cutoff)
            error_rate = (recent_404 / recent_total * 100) if recent_total > 0 else 0.0
            return {
                'unique_urls': len(self.unique_urls),
                'total_requests': recent_total,
                'error_404_count': recent_404,
                'error_rate': round(error_rate, 1),
            }

    def reset(self):
        with self.lock:
            self.unique_urls.clear()
            self.all_request_times.clear()
            self.error_404_times.clear()


DEFAULT_CONFIG = {
    'backend_url': os.environ.get('BACKEND_URL', ''),
    'window_seconds': 60,
    'thresholds': {
        'unique_urls': 50,
        'error_rate_percent': 70.0,
        'min_requests_for_rate': 10,
        'rps': 30,
    },
    'block_duration_seconds': 3600,
    'mode': 'block',
    'whitelist': ['127.0.0.1', '::1'],
    'excluded_paths': ['/waf/', '/admin/', '/static/', '/favicon.ico'],
    'response_codes': {
        'blocked': 403,
    },
}


class ProtectionEngine:
    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.config = self._load_config()
        self._trackers: dict[str, IPTracker] = {}
        self._trackers_lock = threading.Lock()
        self._manual_blocks: dict[str, datetime] = {}
        self._manual_blocks_lock = threading.Lock()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        logger.info('ProtectionEngine инициализирован, конфиг: %s', self.config)

    def _load_config(self) -> dict:
        from django.conf import settings
        cfg_path = getattr(settings, 'WAF_CONFIG_PATH', '')
        config = DEFAULT_CONFIG.copy()
        if cfg_path and os.path.exists(cfg_path):
            try:
                with open(cfg_path, 'r', encoding='utf-8') as f:
                    file_cfg = yaml.safe_load(f) or {}
                config.update(file_cfg)
                if 'thresholds' in file_cfg:
                    config['thresholds'] = {**DEFAULT_CONFIG['thresholds'], **file_cfg['thresholds']}
                logger.info('Конфиг загружен из %s', cfg_path)
            except Exception as e:
                logger.error('Ошибка загрузки конфига: %s', e)
        return config

    def reload_config(self):
        self.config = self._load_config()

    def _get_tracker(self, ip: str) -> IPTracker:
        with self._trackers_lock:
            if ip not in self._trackers:
                self._trackers[ip] = IPTracker(self.config['window_seconds'])
            return self._trackers[ip]

    def _is_whitelisted(self, ip: str) -> bool:
        for entry in self.config.get('whitelist', []):
            try:
                if '/' in entry:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                        return True
                elif ip == entry:
                    return True
            except ValueError:
                pass
        return False

    def _is_excluded_path(self, path: str) -> bool:
        for excluded in self.config.get('excluded_paths', []):
            if path.startswith(excluded):
                return True
        return False

    def is_blocked(self, ip: str) -> bool:
        if self._is_whitelisted(ip):
            return False
        with self._manual_blocks_lock:
            if ip in self._manual_blocks:
                expires = self._manual_blocks[ip]
                if expires is None or datetime.now(timezone.utc) < expires:
                    return True
                else:
                    del self._manual_blocks[ip]
        try:
            from waf.models import BlockedIP
            from django.utils import timezone as dj_tz
            block = BlockedIP.objects.filter(ip_address=ip, is_active=True).first()
            if block:
                if block.expires_at and dj_tz.now() > block.expires_at:
                    block.is_active = False
                    block.save(update_fields=['is_active'])
                    return False
                return True
        except Exception:
            pass
        return False

    def check_and_record(self, ip: str, url: str, path: str, method: str,
                          status_code: Optional[int], user_agent: str = '') -> dict:
        result = {
            'action': 'allow',
            'reason': None,
            'stats': {},
        }

        if self._is_whitelisted(ip):
            result['action'] = 'whitelist'
            return result

        if self._is_excluded_path(path):
            result['action'] = 'allow'
            return result

        if self.is_blocked(ip):
            result['action'] = 'block'
            result['reason'] = 'ip_already_blocked'
            self._record_blocked_event(ip, url, method, user_agent, status_code, 'ip_already_blocked')
            return result

        tracker = self._get_tracker(ip)
        ts = time.time()
        tracker.add_request(url, status_code, ts)
        stats = tracker.get_stats(ts)
        result['stats'] = stats

        thresholds = self.config.get('thresholds', {})
        unique_limit = thresholds.get('unique_urls', 50)
        error_rate_limit = thresholds.get('error_rate_percent', 70.0)
        min_requests = thresholds.get('min_requests_for_rate', 10)
        rps_limit = thresholds.get('rps', 30)

        window = self.config.get('window_seconds', 60)
        rps = stats['total_requests'] / window if window > 0 else 0

        violation_reason = None

        if stats['unique_urls'] >= unique_limit:
            violation_reason = 'unique_url_limit'
        elif stats['total_requests'] >= min_requests and stats['error_rate'] >= error_rate_limit:
            violation_reason = 'error_rate_limit'
        elif rps >= rps_limit:
            violation_reason = 'rps_limit'

        if violation_reason:
            mode = self.config.get('mode', 'block')
            if mode in ('block', 'monitoring'):
                self._block_ip(ip, violation_reason, stats)
                if mode == 'block':
                    result['action'] = 'block'
                    result['reason'] = violation_reason
                else:
                    result['action'] = 'monitor'
                    result['reason'] = violation_reason
            self._record_attack_event(ip, url, method, user_agent, status_code, violation_reason, stats)
        elif stats['unique_urls'] >= int(unique_limit * 0.7):
            result['action'] = 'warn'
            result['reason'] = 'approaching_limit'
            self._record_warning_event(ip, url, method, user_agent, stats)

        return result

    def _block_ip(self, ip: str, reason: str, stats: dict):
        from waf.models import BlockedIP
        from django.utils import timezone as dj_tz
        import datetime as dt

        duration = self.config.get('block_duration_seconds', 3600)
        expires = dj_tz.now() + dt.timedelta(seconds=duration) if duration > 0 else None
        try:
            block, created = BlockedIP.objects.update_or_create(
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

    def _record_blocked_event(self, ip, url, method, user_agent, status_code, reason):
        self._save_event('blocked_request', ip, url, method, user_agent, status_code, {
            'reason': reason
        })

    def _record_attack_event(self, ip, url, method, user_agent, status_code, reason, stats):
        self._save_event('attack_detected', ip, url, method, user_agent, status_code, {
            'reason': reason,
            'unique_urls': stats.get('unique_urls'),
            'total_requests': stats.get('total_requests'),
            'error_rate': stats.get('error_rate'),
        }, stats)
        from waf.logger import log_event
        log_event('attack_detected', ip, url=url, method=method, reason=reason, stats=stats)

    def _record_warning_event(self, ip, url, method, user_agent, stats):
        self._save_event('threshold_warning', ip, url, method, user_agent, None, {
            'unique_urls': stats.get('unique_urls'),
        }, stats)

    def _save_event(self, event_type, ip, url, method, user_agent,
                    status_code, details, stats=None):
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

    def manual_block(self, ip: str, duration_seconds: int = 3600, reason: str = 'manual'):
        stats = {}
        tracker = self._trackers.get(ip)
        if tracker:
            stats = tracker.get_stats(time.time())
        self._block_ip(ip, reason, stats)

    def manual_unblock(self, ip: str):
        try:
            from waf.models import BlockedIP
            BlockedIP.objects.filter(ip_address=ip).update(is_active=False)
            with self._manual_blocks_lock:
                self._manual_blocks.pop(ip, None)
            tracker = self._trackers.get(ip)
            if tracker:
                tracker.reset()
            from waf.logger import log_event
            log_event('ip_unblocked', ip)
        except Exception as e:
            logger.error('Ошибка разблокировки IP %s: %s', ip, e)

    def get_ip_stats(self, ip: str) -> dict:
        tracker = self._trackers.get(ip)
        if tracker:
            return tracker.get_stats(time.time())
        return {}

    def get_all_trackers_summary(self) -> list:
        ts = time.time()
        result = []
        with self._trackers_lock:
            for ip, tracker in self._trackers.items():
                stats = tracker.get_stats(ts)
                if stats['total_requests'] > 0:
                    result.append({'ip': ip, **stats})
        return sorted(result, key=lambda x: x['unique_urls'], reverse=True)

    def _cleanup_loop(self):
        while True:
            time.sleep(300)
            try:
                ts = time.time()
                window = self.config.get('window_seconds', 60)
                cutoff = ts - window * 3
                with self._trackers_lock:
                    inactive = [
                        ip for ip, tracker in self._trackers.items()
                        if not tracker.all_request_times or tracker.all_request_times[-1] < cutoff
                    ]
                    for ip in inactive:
                        del self._trackers[ip]
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
